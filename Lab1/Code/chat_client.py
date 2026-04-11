import socket 
from threading import Thread
import json
from config import DEFAULT_ALGORITHM, SERVER_IP, SERVER_PORT
from Crypto_Algorithm import get_crypto
from datetime import datetime
import queue

class Colors:
    GREEN = '\033[92m'    # 绿色 - 发送的消息
    BLUE = '\033[94m'     # 蓝色 - 接收的消息
    RED = '\033[91m'      # 红色 - 错误信息
    END = '\033[0m'       # 重置颜色

# 选择加密算法
algo = DEFAULT_ALGORITHM  
# 输入用户名
username = input("你的用户名: ")
# 初始化加密模块
crypto = get_crypto(algo, username)
client = socket.socket()
client.connect((SERVER_IP, SERVER_PORT))
# 注册信息
register_data = {
    "type": "register",
    "username": username
}
if algo.upper() in ["RSA", "ECC"]:
    register_data["public_key"] = crypto.export_public_key()

client.send(json.dumps(register_data).encode())
print(f"{Colors.GREEN}✓ 登录成功！{Colors.END}\n")

pubkey_responses = queue.Queue()


# 获取当前时间戳
def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

# 接收信息
def receive():
    while True:
        try:
            msg = client.recv(4096)
            if not msg:
                break
            data = json.loads(msg.decode())
            if data.get("type") == "pubkey":
                pubkey_responses.put(data)
            elif data.get("type") == "message":
                # 提取信息
                sender = data["from"]
                ciphertext = data["ciphertext"]
                signature = data.get("signature")
                sender_pub = data.get("sender_pub_key")
                # 只有非对称算法才需要验证签名
                if algo.upper() in ["RSA", "ECC"] and signature:
                    if not crypto.verify(ciphertext, signature, sender_public_key=sender_pub):
                        print(f"{Colors.RED}{sender}: 签名验证失败{Colors.END}")
                        continue
                plaintext = crypto.decrypt(ciphertext)
                print(f"{Colors.BLUE}[{get_timestamp()}]{sender}: {plaintext}{Colors.END}")
                print(f"{Colors.GREEN}", end="", flush=True)
        except Exception as e:
            print("接收异常:", e)
            break

# 发送消息
def send():
    while True:
        print(f"{Colors.GREEN}", end="")  # 设置颜色
        text = input()  # 输入的文字会变成绿色
        print(f"{Colors.END}", end="")    # 重置颜色
        if ":" not in text:
            print(f"{Colors.RED}格式: 用户名:消息{Colors.END}")
            continue
        target, message = text.split(":", 1)
        if algo.upper() == "RSA":
            # 向服务端请求密钥
            request = {
                    "type": "get_pubkey",
                    "username": target
                }
            client.send(json.dumps(request).encode())
            # 等服务器返回
            try:
                resp_data = pubkey_responses.get(timeout=5)  # 等待最多5秒
            except queue.Empty:
                print("获取公钥超时")
                continue
            receiver_pub = resp_data["public_key"]
            ciphertext = crypto.encrypt(message, receiver_pub)
        else:
            ciphertext = crypto.encrypt(message)
        # 拼接格式
        data = {
            "type": "message",
            "from": username,
            "to": target,
            "ciphertext": ciphertext
        }

        # 非对称算法加签名
        if algo.upper() in ["RSA", "ECC"]:
            signature = crypto.sign(ciphertext)
            data["signature"] = signature

        client.send(json.dumps(data).encode())

if __name__ == "__main__":
    Thread(target=receive, daemon=True).start()
    send()