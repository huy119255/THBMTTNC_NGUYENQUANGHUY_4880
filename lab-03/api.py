from flask import Flask, request, jsonify
from cipher.rsa import RSACipher

app = Flask(__name__)

# Khởi tạo đối tượng RSA
rsa_cipher = RSACipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json
    message = data.get('message', '')
    key_type = data.get('key_type', 'public')
    
    private_key, public_key = rsa_cipher.load_keys()
    
    # Chọn key để mã hóa (thường là public key)
    key = public_key if key_type == 'public' else private_key
    
    try:
        encrypted_message = rsa_cipher.encrypt(message, key)
        return jsonify({'encrypted_message': encrypted_message.hex()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json
    ciphertext_hex = data.get('ciphertext', '')
    key_type = data.get('key_type', 'private') # Mặc định giải mã dùng private key
    
    private_key, public_key = rsa_cipher.load_keys()
    
    # Chọn key để giải mã
    if key_type == 'private':
        key = private_key
    elif key_type == 'public':
        key = public_key
    else:
        return jsonify({'error': 'Invalid key type'}), 400
        
    try:
        # CHÚ Ý: Chuyển hex ngược lại thành bytes trước khi giải mã
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_message = rsa_cipher.decrypt(ciphertext_bytes, key)
        
        # Nếu decrypted_message trả về dạng bytes, hãy .decode() nó
        if isinstance(decrypted_message, bytes):
            decrypted_message = decrypted_message.decode('utf-8')
            
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': f"Decryption failed: {str(e)}"}), 500

# Đừng quên thêm các route cho Sign và Verify nếu bạn cần dùng tính năng đó
@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign():
    data = request.json
    message = data.get('message', '')
    private_key, _ = rsa_cipher.load_keys()
    signature = rsa_cipher.sign(message, private_key)
    return jsonify({'signature': signature.hex()})

@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify():
    data = request.json
    message = data.get('message', '')
    signature_hex = data.get('signature', '')
    _, public_key = rsa_cipher.load_keys()
    
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        is_verified = rsa_cipher.verify(message, signature_bytes, public_key)
        return jsonify({'is_verified': is_verified})
    except:
        return jsonify({'is_verified': False})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)