import socket
from threading import Thread
import json

# 存储客户端及映射关系 username -> {"conn": socket, "public_key": str}
users = {}

# 消息转发
def forward_message(data):
    try:
        # 提取发送方和接收方
        msg = json.loads(data.decode())
        receiver = msg["to"]

        if receiver in users:
            # 需要获取conn对象
            users[receiver]["conn"].send(data)
    except:
        pass

# 客户端处理
def handle_client(conn):
    username = None
    try:
        # 第一次发送消息时注册用户名
        data = conn.recv(4096)
        msg = json.loads(data.decode())

        if msg["type"] == "register":
            username = msg["username"]
            public_key = msg.get("public_key")
            users[username] = {"conn": conn, "public_key": public_key}
            print(f"{username} connected")
        
        # 消息处理循环
        while True:
            data = conn.recv(4096)
            if not data:
                break
                
            msg = json.loads(data.decode())
            
            # 判断消息类型
            if msg["type"] == "message":
                target = msg["to"]
                sender = msg["from"]
                if target in users:
                    # 转发消息并附加发送者公钥
                    if users[sender]["public_key"]:
                        msg["sender_pub_key"] = users[sender]["public_key"]
                    users[target]["conn"].send(json.dumps(msg).encode())
            # 请求消息，发送对应的公钥
            elif msg["type"] == "get_pubkey":
                target = msg["username"]
                if target in users:
                    response = {
                        "type": "pubkey",
                        "public_key": users[target]["public_key"]
                    }
                conn.send(json.dumps(response).encode())
            else:
                # 其他类型消息直接转发
                forward_message(data)
                
    except Exception as e:
        print(f"处理错误: {e}")
    
    # 用户断开
    conn.close()
    for name, info in list(users.items()):
        if info["conn"] == conn:
            del users[name]
            print(f"{username} disconnected")

# 服务端启动
def start():
    # 创建SOCKET
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定地址
    server.bind(("0.0.0.0", 9000))
    # 监听
    server.listen()

    print("Secure Chat Server Started")
    # 建立连接循环
    while True:
        # 阻塞等待客户端连接
        conn, addr = server.accept()

        print("New connection:", addr)
        # 多线程
        thread = Thread(
            target=handle_client,
            args=(conn,),
            daemon=True
        )
        thread.start()

if __name__ == "__main__":
    try:
        start()
    except KeyboardInterrupt:
        print("服务器已停止")