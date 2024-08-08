import des 
import socket

HOST = "127.0.0.1"
PORT = 1234

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = input()
    print(f"data to send {data}")
    enc   = des.encryption(data)
    s.send(enc.encode())

