import ssl
import socket
import hashlib
import base64
import json
import os
import urllib.parse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def get_ios_style_ec_public_key_bytes(public_key):
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.public_bytes(
            Encoding.X962,  # 重点：X9.62 表示 raw ECPoint 格式（iOS返回值相同）
            PublicFormat.UncompressedPoint
        )
    else:
        return public_key.public_bytes(Encoding.DER, PublicFormat.PKCS1) 

def get_leaf_cert_public_key_hash(url, port=443):
    # 从 URL 中提取主机名
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.netloc
    
    # 建立 TLS 连接并获取证书链
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
    conn.settimeout(5)
    conn.connect((hostname, port))
    der_cert_chain = conn.getpeercert(binary_form=True)  # 获取 Leaf 证书（第 0 个）
    conn.close()

    # 解析证书
    cert = x509.load_der_x509_certificate(der_cert_chain, backend=default_backend())
    public_key = cert.public_key()

    # 获取公钥二进制数据（DER 格式）
    public_bytes = get_ios_style_ec_public_key_bytes(public_key)

    # 计算 SHA256
    sha256_hash = hashlib.sha256(public_bytes).digest()
    # 输出 Base64 格式的 pin（符合 TLS pinning 通常格式）
    base64_hash = base64.b64encode(sha256_hash).decode()

    return base64_hash

def is_valid_hash(hash_value):
    """检查哈希值是否在有效哈希列表中"""
    try:
        with open('ValidAICertificatesHash.json', 'r') as f:
            valid_hashes = json.load(f)['hashs']
        return hash_value in valid_hashes
    except Exception as e:
        print(f"检查哈希值时出错: {e}")
        return False

def add_hash_to_valid_list(hash_value):
    """将哈希值添加到有效哈希列表中"""
    try:
        # 如果文件不存在，创建一个新的
        if not os.path.exists('ValidAICertificatesHash.json'):
            with open('ValidAICertificatesHash.json', 'w') as f:
                json.dump({"hashs": []}, f, indent=4)
        
        with open('ValidAICertificatesHash.json', 'r') as f:
            valid_hashes_data = json.load(f)
        
        if hash_value not in valid_hashes_data['hashs']:
            valid_hashes_data['hashs'].append(hash_value)
            
            with open('ValidAICertificatesHash.json', 'w') as f:
                json.dump(valid_hashes_data, f, indent=4)
            print(f"哈希值已添加到有效列表中")
        else:
            print(f"哈希值已存在于有效列表中")
    except Exception as e:
        print(f"添加哈希值时出错: {e}")

def main():
    # 需要检查的 API URLs
    api_urls = [
        "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
        "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "https://api.openai.com/v1/chat/completions",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "https://api.minimaxi.com/v1/t2a_v2",
        "https://api-uw.minimax.io/v1/t2a_v2"
    ]
    
    for url in api_urls:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        
        try:
            key_hash = get_leaf_cert_public_key_hash(url)
            print(f"\nSHA256 Pin for {hostname} (Leaf cert): {key_hash}")
            
            # 检查哈希值是否有效
            if is_valid_hash(key_hash):
                print(f"状态: 证书哈希值有效 ✓")
            else:
                print(f"状态: 证书哈希值无效 ✗")
                # 自动添加到有效列表
                print(f"自动将哈希值添加到有效列表中...")
                add_hash_to_valid_list(key_hash)
        except Exception as e:
            print(f"获取 {hostname} 的证书哈希值时出错: {e}")

if __name__ == "__main__":
    main()