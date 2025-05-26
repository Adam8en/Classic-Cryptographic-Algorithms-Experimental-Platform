from flask import Blueprint, request, jsonify, current_app

try:
    from app.core_algorithms.ecc_manual.ecc_core import (
        generate_ecc_keys as ecc_generate_keys,
        encrypt_message_ecc as ecc_encrypt,
        decrypt_message_ecc as ecc_decrypt,
        secp256k1_curve, 
        CurvePoint, 
        ECCKeyGenerationError, ECIESEncryptionError, ECIESDecryptionError
    )
except ImportError as e:

    def ecc_generate_keys(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    def ecc_encrypt(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    def ecc_decrypt(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    class ECCKeyGenerationError(Exception): pass
    class ECIESEncryptionError(Exception): pass
    class ECIESDecryptionError(Exception): pass
    secp256k1_curve = None 
    class CurvePoint: pass 

ecc_api_bp = Blueprint('ecc_api_bp', __name__)

@ecc_api_bp.route('/ecc/generate_keys', methods=['POST'])
def ecc_generate_keys_api():
    try:

        if not secp256k1_curve:
            raise ECCKeyGenerationError("默认曲线 secp256k1 未加载。")

        private_key_d, public_key_point_Q = ecc_generate_keys(curve=secp256k1_curve)

        response_data = {
            'private_key_d': str(private_key_d),
            'public_key_qx': str(public_key_point_Q.x),
            'public_key_qy': str(public_key_point_Q.y),
            'curve_name': 'secp256k1' 
        }
        return jsonify({'success': True, 'message': 'ECC密钥生成成功！', 'keys': response_data})
    except (ECCKeyGenerationError, ValueError, TypeError) as e:
        current_app.logger.error(f"ECC密钥生成API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的ECC密钥生成API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '密钥生成时发生内部错误。'}), 500

@ecc_api_bp.route('/ecc/encrypt', methods=['POST'])
def ecc_encrypt_api():
    try:
        data = request.json
        plaintext_str = data.get('plaintext')
        recipient_qx_str = data.get('public_key_qx')
        recipient_qy_str = data.get('public_key_qy')

        if not all([plaintext_str, recipient_qx_str, recipient_qy_str]):
            return jsonify({'success': False, 'message': '缺少必要的加密参数：明文、接收方公钥Qx, Qy。'}), 400

        if not secp256k1_curve: 
            return jsonify({'success': False, 'message': '曲线参数未加载。'}), 500

        recipient_qx = int(recipient_qx_str)
        recipient_qy = int(recipient_qy_str)

        try:
            recipient_public_key_point = CurvePoint(secp256k1_curve, recipient_qx, recipient_qy)
            if not secp256k1_curve.is_on_curve(recipient_public_key_point):
                return jsonify({'success': False, 'message': '提供的接收方公钥点不在曲线上。'}), 400
        except Exception as e:
            return jsonify({'success': False, 'message': f'无效的公钥点坐标: {e}'}), 400

        message_bytes = plaintext_str.encode('utf-8')

        ephemeral_public_key_R, ciphertext_bytes = ecc_encrypt(
            recipient_public_key_point, 
            message_bytes, 
            curve=secp256k1_curve
        )

        return jsonify({
            'success': True, 
            'message': 'ECC加密成功！', 
            'ephemeral_R_x': str(ephemeral_public_key_R.x),
            'ephemeral_R_y': str(ephemeral_public_key_R.y),
            'ciphertext_hex': ciphertext_bytes.hex()
        })
    except (ECIESEncryptionError, ValueError, TypeError) as e:
        current_app.logger.error(f"ECC加密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的ECC加密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '加密时发生内部错误。'}), 500

@ecc_api_bp.route('/ecc/decrypt', methods=['POST'])
def ecc_decrypt_api():
    try:
        data = request.json
        ephemeral_R_x_str = data.get('ephemeral_R_x')
        ephemeral_R_y_str = data.get('ephemeral_R_y')
        ciphertext_hex = data.get('ciphertext_hex')
        private_key_d_str = data.get('private_key_d')

        if not all([ephemeral_R_x_str, ephemeral_R_y_str, ciphertext_hex, private_key_d_str]):
            return jsonify({'success': False, 'message': '缺少必要的解密参数：临时公钥R(x,y), 密文, 或私钥d。'}), 400

        if not secp256k1_curve:
            return jsonify({'success': False, 'message': '曲线参数未加载。'}), 500

        ephemeral_R_x = int(ephemeral_R_x_str)
        ephemeral_R_y = int(ephemeral_R_y_str)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        private_key_d = int(private_key_d_str)

        try:
            ephemeral_public_key_R = CurvePoint(secp256k1_curve, ephemeral_R_x, ephemeral_R_y)
            if not secp256k1_curve.is_on_curve(ephemeral_public_key_R):
                return jsonify({'success': False, 'message': '提供的临时公钥点R不在曲线上。'}), 400
        except Exception as e:
            return jsonify({'success': False, 'message': f'无效的临时公钥点R坐标: {e}'}), 400

        decrypted_bytes = ecc_decrypt(
            private_key_d, 
            ephemeral_public_key_R, 
            ciphertext_bytes, 
            curve=secp256k1_curve
        )

        decrypted_text = decrypted_bytes.decode('utf-8', errors='replace')

        return jsonify({
            'success': True, 
            'message': 'ECC解密成功！', 
            'decrypted_text': decrypted_text
        })
    except (ECIESDecryptionError, ValueError, TypeError) as e:
        current_app.logger.error(f"ECC解密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"未预期的ECC解密API错误: {e}", exc_info=True)
        return jsonify({'success': False, 'message': '解密时发生内部错误。'}), 500