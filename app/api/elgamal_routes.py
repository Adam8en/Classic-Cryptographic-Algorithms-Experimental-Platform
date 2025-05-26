# app/api/elgamal_routes.py

from flask import Blueprint, request, jsonify, current_app

try:
    from app.core_algorithms.elgamal_manual.elgamal_core import (
        generate_keys as elgamal_generate_keys,
        encrypt as elgamal_encrypt,
        decrypt as elgamal_decrypt,
        ElGamalKeyGenerationError, ElGamalEncryptionError, ElGamalDecryptionError
    )
except ImportError as e:

    def elgamal_generate_keys(*args, **kwargs): raise NotImplementedError(f"ElGamal模块未加载: {e}")
    def elgamal_encrypt(*args, **kwargs): raise NotImplementedError(f"ElGamal模块未加载: {e}")
    def elgamal_decrypt(*args, **kwargs): raise NotImplementedError(f"ElGamal模块未加载: {e}")
    class ElGamalKeyGenerationError(Exception): pass
    class ElGamalEncryptionError(Exception): pass
    class ElGamalDecryptionError(Exception): pass

elgamal_api_bp = Blueprint('elgamal_api_bp', __name__)

@elgamal_api_bp.route('/elgamal/generate_keys', methods=['POST'])
def elgamal_generate_keys_api():
    try:
        data = request.json
        bits = int(data.get('bits', 512)) 

        public_key, private_key_x = elgamal_generate_keys(bits=bits)
        p, g, y = public_key

        response_data = {
            'public_key_p': str(p),
            'public_key_g': str(g),
            'public_key_y': str(y),
            'private_key_x': str(private_key_x),
        }
        return jsonify({'success': True, 'message': 'ElGamal密钥生成成功！', 'keys': response_data})
    except (ElGamalKeyGenerationError, ValueError, TypeError) as e:
        current_app.logger.error(f"ElGamal密钥生成API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的ElGamal密钥生成API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '密钥生成时发生内部错误。'}), 500

@elgamal_api_bp.route('/elgamal/encrypt', methods=['POST'])
def elgamal_encrypt_api():
    try:
        data = request.json
        plaintext_str = data.get('plaintext')
        p_str = data.get('public_key_p')
        g_str = data.get('public_key_g')
        y_str = data.get('public_key_y')

        if not all([plaintext_str, p_str, g_str, y_str]):
            return jsonify({'success': False, 'message': '缺少必要的加密参数：明文、公钥p, g, y。'}), 400

        p = int(p_str)
        g = int(g_str)
        y = int(y_str)

        message_bytes = plaintext_str.encode('utf-8')
        message_int = int.from_bytes(message_bytes, byteorder='big')

        if message_int >= p:
            return jsonify({'success': False, 'message': f'明文转换后的整数 ({message_int}) 过大，必须小于素数 p ({p})。请尝试更短的明文或更大的密钥位数。'}), 400

        public_key_tuple = (p, g, y)

        c1, c2 = elgamal_encrypt(public_key_tuple, message_int)
        return jsonify({
            'success': True, 
            'message': 'ElGamal加密成功！', 
            'ciphertext_c1': str(c1),
            'ciphertext_c2': str(c2)
        })
    except (ElGamalEncryptionError, ValueError, TypeError) as e:
        current_app.logger.error(f"ElGamal加密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的ElGamal加密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '加密时发生内部错误。'}), 500

@elgamal_api_bp.route('/elgamal/decrypt', methods=['POST'])
def elgamal_decrypt_api():
    try:
        data = request.json
        c1_str = data.get('ciphertext_c1')
        c2_str = data.get('ciphertext_c2')
        p_str = data.get('public_key_p_dec') 
        g_str = data.get('public_key_g_dec') 
        private_key_x_str = data.get('private_key_x_dec')

        if not all([c1_str, c2_str, p_str, g_str, private_key_x_str]):
            return jsonify({'success': False, 'message': '缺少必要的解密参数：c1, c2, p, g, 或私钥x。'}), 400

        c1 = int(c1_str)
        c2 = int(c2_str)
        p = int(p_str)
        g = int(g_str) 
        private_key_x = int(private_key_x_str)

        ciphertext_tuple = (c1, c2)

        decrypted_int = elgamal_decrypt(private_key_x, p, g, ciphertext_tuple)

        try:
            num_bytes = (decrypted_int.bit_length() + 7) // 8
            if decrypted_int == 0: 
                num_bytes = 1 
            decrypted_bytes = decrypted_int.to_bytes(num_bytes, byteorder='big')
            decrypted_text = decrypted_bytes.decode('utf-8', errors='replace')
        except OverflowError: 
             if decrypted_int == 0:
                 decrypted_text = "" 
             else:
                 raise 
        except UnicodeDecodeError:
            decrypted_text = decrypted_bytes.hex() + " (无法UTF-8解码，显示为Hex)"

        return jsonify({
            'success': True, 
            'message': 'ElGamal解密成功！', 
            'decrypted_text': decrypted_text
        })
    except (ElGamalDecryptionError, ValueError, TypeError) as e:
        current_app.logger.error(f"ElGamal解密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的ElGamal解密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '解密时发生内部错误。'}), 500