import rsa



class RSACipher:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        # Định nghĩa hàm tạo cặp khóa 512-bit
        (self.public_key, self.private_key) = rsa.newkeys(1024)
        with open("private.pem", "wb") as f:
            f.write(self.private_key.save_pkcs1())
        with open("public.pem", "wb") as f:
            f.write(self.public_key.save_pkcs1())

    def load_keys(self):
        # Định nghĩa hàm tải khóa từ file .pem
        with open("private.pem", "rb") as f:
            self.private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open("public.pem", "rb") as f:
            self.public_key = rsa.PublicKey.load_pkcs1(f.read())
        return self.private_key, self.public_key

    def encrypt(self, message, key):
        # Định nghĩa hàm mã hóa văn bản
        return rsa.encrypt(message.encode('utf8'), key)

    def decrypt(self, ciphertext, key):
        # Định nghĩa hàm giải mã văn bản
        return rsa.decrypt(ciphertext, key).decode('utf8')

    def sign(self, message, key):
        # Định nghĩa hàm ký số
        return rsa.sign(message.encode('utf8'), key, 'SHA-1')

    def verify(self, message, signature, key):
        # Định nghĩa hàm xác thực chữ ký
        try:
            return rsa.verify(message.encode('utf8'), signature, key) == 'SHA-1'
        except:
            return False
