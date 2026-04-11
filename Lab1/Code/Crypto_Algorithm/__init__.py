from .crypto_aes import AES_Crypto
from .crypto_des import DES_Crypto
from .crypto_rsa import RSA_Crypto
from .crypto_ecc import ECC_Crypto

# 加密算法映射
crypto_map = {
    "AES": AES_Crypto,
    "DES": DES_Crypto,
    "RSA": RSA_Crypto,
    "ECC": ECC_Crypto
}

def get_crypto(algo, username=None):
    algo = algo.upper()
    if algo == "AES":
        from .crypto_aes import AES_Crypto
        return AES_Crypto()
    elif algo == "DES":
        from .crypto_des import DES_Crypto
        return DES_Crypto()
    elif algo == "RSA":
        from .crypto_rsa import RSA_Crypto
        return RSA_Crypto(username)
    elif algo == "ECC":
        from .crypto_ecc import ECC_Crypto
        return ECC_Crypto(username)