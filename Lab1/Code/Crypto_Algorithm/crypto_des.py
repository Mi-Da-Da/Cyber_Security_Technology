from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from base64 import *
import os
import sys

sys.path.append(
    os.path.dirname(os.path.dirname(__file__))
)

from config import DES_KEY, HMAC_KEY

class DES_Crypto:
    # 初始化
    def __init__(self):
        self.key = DES_KEY
        self.hmac_key = HMAC_KEY

    # 加密
    def encrypt(self, plaintext):
        iv = get_random_bytes(8)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(
            pad(plaintext.encode(), DES.block_size)
        )
        data = iv + ciphertext

        return b64encode(data).decode()
    
    # 解密
    def decrypt(self, cipherdata):
        data = b64decode(cipherdata)
        iv = data[:8]
        ciphertext = data[8:]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        plaintext = unpad(
            cipher.decrypt(ciphertext), 
            DES.block_size
        )

        return plaintext.decode()
    
    # 签名
    def sign(self, message):
        # 创建HMAC对象并计算hmac值
        h = HMAC.new(self.hmac_key, digestmod=SHA256)
        h.update(message.encode())

        return b64encode(h.digest()).decode()

    # 验证签名
    def verify(self, message, signature):
        # 重新计算HMAC值并比较
        h = HMAC.new(self.hmac_key, digestmod=SHA256)
        h.update(message.encode())

        try:
            h.verify(b64decode(signature))
            return True
        except:
            return False