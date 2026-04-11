from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from base64 import *
import os

class ECC_Crypto:
    # 初始化
    def __init__(self, username):
        os.makedirs("ecc_private_key", exist_ok=True)
        self.key_file = os.path.join("ecc_private_key", f"{username}_ecc_private.pem")
        # 如果私钥存在就读取
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        # 不存在就生成
        else:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            with open(self.key_file, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
        self.public_key = self.private_key.public_key()
        
    # 导出公钥至服务端
    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # 加密
    def encrypt(self, plaintext):
        # ECC一般不直接加密消息
        return plaintext
    # 解密
    def decrypt(self, ciphertext):
        return ciphertext
    # 签名
    def sign(self, message):
        signature = self.private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )

        return b64encode(signature).decode()
    # 验证签名
    def verify(self, message, signature, sender_public_key=None):
        if sender_public_key:
            # 如果公钥是字符串（PEM格式），将字符串编码为字节，然后加载为公钥对象
            if isinstance(sender_public_key, str):
                pub_key = serialization.load_pem_public_key(sender_public_key.encode())
            else:
                pub_key = sender_public_key
        # 验证
        try:
            pub_key.verify(b64decode(signature), message.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False