# app/api/rsa_api.py

from flask import Blueprint, request, jsonify, current_app

try:
    from app.core_algorithms.rsa_manual.rsa_core import (
        generate_keys as rsa_generate_keys,
        encrypt_with_padding as rsa_encrypt,
        decrypt_with_padding as rsa_decrypt,
        RSADecryptionError, RSAEncryptionError, RSAKeyGenerationError
    )
except ImportError as e:
    def rsa_generate_keys(*args, **kwargs): raise NotImplementedError(f"RSA模块未加载: {e}")
    def rsa_encrypt(*args, **kwargs): raise NotImplementedError(f"RSA模块未加载: {e}")
    def rsa_decrypt(*args, **kwargs): raise NotImplementedError(f"RSA模块未加载: {e}")
    class RSAKeyGenerationError(Exception): pass
    class RSAEncryptionError(Exception): pass
    class RSADecryptionError(Exception): pass

rsa_api_bp = Blueprint('rsa_api_bp',__name__)

@rsa_api_bp.route('/rsa/generate_keys', methods=['POST'])
def rsa_generate_keys_api():
    try:
        data = request.json
        bits = int(data.get('bits', 2048))
        e_value = int(data.get('e_value', 65537))

        public_key, private_key = rsa_generate_keys(bits= bits, e_value= e_value)

        response_data = {
            'public_key_n': str(public_key[0]),
            'public_key_e': str(public_key[1]),
            'private_key_d': str(private_key[1]),
            'private_key_n_for_consistency': str(private_key[0])
        }
        return jsonify({'success': True, 'message': '密钥生成成功', 'keys': response_data})
    except (RSAKeyGenerationError, ValueError, TypeError) as e:
        current_app.logger.error(f"RSA密钥生成API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的RSA密钥生成API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '密钥生成时发生内部错误。'}), 500
    
@rsa_api_bp.route('/rsa/encrypt', methods=['POST'])
def rsa_encrypt_api():
    try:
        data = request.json
        plaintext_str = data.get('plaintext')
        public_key_n_str = data.get('public_key_n')
        public_key_e_str = data.get('public_key_e')

        if not all([plaintext_str, public_key_n_str, public_key_e_str]):
            return jsonify({'success': False, 'message': '缺少必要的加密参数：明文、公钥N或公钥E。'}), 400

        public_key_n = int(public_key_n_str)
        public_key_e = int(public_key_e_str)
        message_bytes = plaintext_str.encode('utf-8')
        public_key_tuple = (public_key_n, public_key_e)
        
        ciphertext_bytes = rsa_encrypt(public_key_tuple, message_bytes)
        return jsonify({
            'success': True, 
            'message': '加密成功！', 
            'ciphertext_hex': ciphertext_bytes.hex()
        })
    except (RSAEncryptionError, ValueError, TypeError) as e:
        current_app.logger.error(f"RSA加密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的RSA加密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '加密时发生内部错误。'}), 500

@rsa_api_bp.route('/rsa/decrypt', methods=['POST'])
def rsa_decrypt_api():
    try:
        data = request.json
        ciphertext_hex = data.get('ciphertext_hex')
        private_key_n_str = data.get('private_key_n')
        private_key_d_str = data.get('private_key_d')

        if not all([ciphertext_hex, private_key_n_str, private_key_d_str]):
            return jsonify({'success': False, 'message': '缺少必要的解密参数：密文、私钥N或私钥D。'}), 400
            
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        private_key_n = int(private_key_n_str)
        private_key_d = int(private_key_d_str)
        private_key_tuple = (private_key_n, private_key_d)
        
        decrypted_bytes = rsa_decrypt(private_key_tuple, ciphertext_bytes)
        return jsonify({
            'success': True, 
            'message': '解密成功！', 
            'decrypted_text': decrypted_bytes.decode('utf-8', errors='replace')
        })
    except (RSADecryptionError, ValueError, TypeError) as e:
        current_app.logger.error(f"RSA解密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的RSA解密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '解密时发生内部错误。'}), 500