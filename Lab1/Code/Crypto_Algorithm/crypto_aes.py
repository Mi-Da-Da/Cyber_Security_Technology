from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import base64
import os
import sys

sys.path.append(
    os.path.dirname(os.path.dirname(__file__))
)

from config import AES_KEY, HMAC_KEY

class AES_Crypto:
    # 初始化
    def __init__(self):
        self.key = AES_KEY
        self.hmac_key = HMAC_KEY
    # 加密
    def encrypt(self, plaintext):
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(
            pad(plaintext.encode(), AES.block_size)
        )

        return base64.b64encode(iv + ciphertext).decode()
    # 解密
    def decrypt(self, cipherdata):
        data = base64.b64decode(cipherdata)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(
            cipher.decrypt(ciphertext),
            AES.block_size
        )

        return plaintext.decode()
    # 签名
    def sign(self, message):
        h = HMAC.new(self.hmac_key, digestmod=SHA256)
        h.update(message.encode())

        return base64.b64encode(h.digest()).decode()
    # 验证签名
    def verify(self, message, signature):
        h = HMAC.new(self.hmac_key, digestmod=SHA256)
        h.update(message.encode())

        try:
            h.verify(base64.b64decode(signature))
            return True
        except:
            return False