import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode

class RSA_Crypto:
    # 初始化
    def __init__(self, username, key_size=2048):
        os.makedirs("rsa_private_key", exist_ok=True)
        self.key_file = os.path.join("rsa_private_key", f"{username}_rsa_private.pem")
        # 如果私钥存在就读取
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                self.private_key = RSA.import_key(f.read())
        # 不存在就生成
        else:
            key = RSA.generate(key_size)
            self.private_key = key
            with open(self.key_file, "wb") as f:
                f.write(key.export_key())
        self.public_key = self.private_key.publickey()

    # 导出公钥
    def export_public_key(self):
        return self.public_key.export_key().decode()
    
    # 加密
    def encrypt(self, plaintext, receiver_public_key=None):
        pub_key = RSA.import_key(receiver_public_key.encode())
        cipher = PKCS1_OAEP.new(pub_key)
        ciphertext = cipher.encrypt(plaintext.encode())

        return b64encode(ciphertext).decode()

    # 解密
    def decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.private_key)
        plaintext = cipher.decrypt(
            b64decode(ciphertext)
        )

        return plaintext.decode()

    # 签名
    def sign(self, message):
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(self.private_key).sign(h)

        return b64encode(signature).decode()

    # 验证签名
    def verify(self, message, signature, sender_public_key=None):
        try:
            if sender_public_key:
                pub_key = RSA.import_key(sender_public_key.encode())
            else:
                pub_key = self.public_key
            h = SHA256.new(message.encode())
            pkcs1_15.new(pub_key).verify(
                h,
                b64decode(signature)
            )
            return True
        except:
            return False