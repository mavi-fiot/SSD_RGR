import socket
import os
import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def log(label, value):
    print(f"[{label}] {value}")

#  SSL 
CERT_FILE = r"C:\Users\scrib\server.crt"
KEY_FILE = r"C:\Users\scrib\server.key"

# Генерація RSA ключів сервера
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()

server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def generate_session_key(premaster, client_random, server_random):
    key_material = premaster + client_random + server_random
    session_key = hashlib.sha256(key_material).digest()
    log("Сеансовий ключ", session_key.hex())
    return session_key

def encrypt_message(message, session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message.encode()) + encryptor.finalize()
    return encrypted, encryptor.tag

def decrypt_message(ciphertext, tag, session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted.decode()

def server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('localhost', 65432))
        sock.listen()
        with context.wrap_socket(sock, server_side=True) as secure_sock:
            print("[Сервер] Очікування клієнта...")
            conn, addr = secure_sock.accept()
            with conn:
                print(f"[Сервер] Підключено клієнта {addr}")
                conn.sendall(server_public_pem)
                
                client_hello = conn.recv(1024).decode()
                log("Сервер", f"Отримано привіт: {client_hello}")
                server_hello = os.urandom(16).hex()
                conn.sendall(server_hello.encode())
                
                enc_premaster = conn.recv(256)
                premaster = server_private_key.decrypt(
                    enc_premaster,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                log("Сервер", f"Premaster секрет: {premaster.hex()}")
                
                server_random = os.urandom(16)
                client_random = conn.recv(16)
                session_key = generate_session_key(premaster, client_random, server_random)
                conn.sendall(server_random)
                
                iv = os.urandom(12)
                conn.sendall(iv)
                
                enc_ready_msg = conn.recv(1024)
                tag = conn.recv(16)
                ready_msg = decrypt_message(enc_ready_msg, tag, session_key, iv)
                log("Сервер", f"Отримано: {ready_msg}")
                
                enc_response, tag = encrypt_message('Привіт! Сеанс встановлено', session_key, iv)
                conn.sendall(enc_response)
                conn.sendall(tag)

def client():
    # 1. Створюємо SSL-контекст і додаємо серверний сертифікат
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("C:/Users/scrib/server.crt")  # Вказуємо сертифікат

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # 2. Обгортаємо сокет у SSL
        with context.wrap_socket(sock, server_hostname='localhost') as secure_sock:
            secure_sock.connect(('localhost', 65432))

            # 3. Отримуємо відкритий ключ сервера
            server_public_pem = secure_sock.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_pem)

            # 4. Відправляємо "випадкове привіт"
            client_hello = os.urandom(16).hex()
            secure_sock.sendall(client_hello.encode())
            server_hello = secure_sock.recv(1024).decode()
            log("Клієнт", f"Отримано привіт сервера: {server_hello}")

            # 5. Генеруємо та шифруємо premaster
            premaster = os.urandom(32)
            enc_premaster = server_public_key.encrypt(
                premaster,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            secure_sock.sendall(enc_premaster)

            # 6. Генеруємо випадкові значення
            client_random = os.urandom(16)
            secure_sock.sendall(client_random)
            server_random = secure_sock.recv(16)

            # 7. Обчислюємо сесійну ключ
            session_key = generate_session_key(premaster, client_random, server_random)
            iv = secure_sock.recv(12)

            # 8. Шифруємо та надсилаємо повідомлення
            enc_ready_msg, tag = encrypt_message('Клієнт готовий', session_key, iv)
            secure_sock.sendall(enc_ready_msg)
            secure_sock.sendall(tag)

            # 9. Отримуємо відповідь від сервера
            enc_response = secure_sock.recv(1024)
            tag = secure_sock.recv(16)
            response = decrypt_message(enc_response, tag, session_key, iv)
            log("Клієнт", f"Відповідь сервера: {response}")

if __name__ == "__main__":
    choice = input("Запустити сервер (s) або клієнта (c)? ")
    if choice == 's':
        server()
    elif choice == 'c':
        client()

