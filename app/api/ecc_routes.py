# app/api/ecc_routes.py

from flask import Blueprint, request, jsonify, current_app

# 导入你的ECC核心逻辑函数
try:
    from app.core_algorithms.ecc_manual.ecc_core import (
        generate_ecc_keys as ecc_generate_keys,
        encrypt_message_ecc as ecc_encrypt,
        decrypt_message_ecc as ecc_decrypt,
        get_curve_by_name, # 导入获取曲线对象的函数
        CurvePoint,        # 导入点类，用于重建对象
        ECCKeyGenerationError, ECIESEncryptionError, ECIESDecryptionError
    )
except ImportError as e:
    # 提供一个回退，以防模块未找到
    def ecc_generate_keys(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    def ecc_encrypt(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    def ecc_decrypt(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    def get_curve_by_name(*args, **kwargs): raise NotImplementedError(f"ECC模块未加载: {e}")
    class ECCKeyGenerationError(Exception): pass
    class ECIESEncryptionError(Exception): pass
    class ECIESDecryptionError(Exception): pass
    class CurvePoint: pass


# 创建一个名为 'ecc_api_bp' 的蓝图
ecc_api_bp = Blueprint('ecc_api_bp', __name__)

@ecc_api_bp.route('/ecc/generate_keys', methods=['POST'])
def ecc_generate_keys_api():
    try:
        data = request.json
        # 从前端接收要使用的曲线名称，默认为 secp256k1
        curve_name = data.get('curve_name', 'secp256k1')
        
        private_key_d, public_key_point_Q = ecc_generate_keys(curve_name=curve_name)
        
        response_data = {
            'private_key_d': str(private_key_d),
            'public_key_qx': str(public_key_point_Q.x),
            'public_key_qy': str(public_key_point_Q.y),
            'curve_name': curve_name # 将使用的曲线名称返回给前端
        }
        return jsonify({'success': True, 'message': f'ECC密钥 ({curve_name}) 生成成功！', 'keys': response_data})
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
        # 接收曲线名称，这是重建点的关键
        curve_name = data.get('curve_name')

        if not all([plaintext_str, recipient_qx_str, recipient_qy_str, curve_name]):
            return jsonify({'success': False, 'message': '缺少必要的加密参数：明文、接收方公钥Qx, Qy, 或曲线名称。'}), 400

        # 根据名称获取曲线对象
        curve = get_curve_by_name(curve_name)
        
        recipient_qx = int(recipient_qx_str)
        recipient_qy = int(recipient_qy_str)
        
        # 使用正确的曲线对象来重新构造接收方的公钥点
        try:
            recipient_public_key_point = CurvePoint(curve, recipient_qx, recipient_qy)
            if not curve.is_on_curve(recipient_public_key_point):
                return jsonify({'success': False, 'message': '提供的接收方公钥点不在指定的曲线上。'}), 400
        except Exception as e:
            return jsonify({'success': False, 'message': f'无效的公钥点坐标: {e}'}), 400
            
        message_bytes = plaintext_str.encode('utf-8')
        
        ephemeral_public_key_R, ciphertext_bytes = ecc_encrypt(
            recipient_public_key_point, 
            message_bytes
        )
        
        return jsonify({
            'success': True, 
            'message': 'ECC加密成功！', 
            'ephemeral_R_x': str(ephemeral_public_key_R.x),
            'ephemeral_R_y': str(ephemeral_public_key_R.y),
            'ciphertext_hex': ciphertext_bytes.hex(),
            'curve_name': curve_name # 返回曲线名称，以便解密时使用
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
        curve_name = data.get('curve_name') # 解密时也需要曲线名称

        if not all([ephemeral_R_x_str, ephemeral_R_y_str, ciphertext_hex, private_key_d_str, curve_name]):
            return jsonify({'success': False, 'message': '缺少必要的解密参数：临时公钥R(x,y), 密文, 私钥d, 或曲线名称。'}), 400

        curve = get_curve_by_name(curve_name)
            
        ephemeral_R_x = int(ephemeral_R_x_str)
        ephemeral_R_y = int(ephemeral_R_y_str)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        private_key_d = int(private_key_d_str)

        # 使用正确的曲线对象来重新构造临时公钥点R
        try:
            ephemeral_public_key_R = CurvePoint(curve, ephemeral_R_x, ephemeral_R_y)
            if not curve.is_on_curve(ephemeral_public_key_R):
                return jsonify({'success': False, 'message': '提供的临时公钥点R不在指定的曲线上。'}), 400
        except Exception as e:
            return jsonify({'success': False, 'message': f'无效的临时公钥点R坐标: {e}'}), 400
        
        decrypted_bytes = ecc_decrypt(
            private_key_d, 
            ephemeral_public_key_R, 
            ciphertext_bytes
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