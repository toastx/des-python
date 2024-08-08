import des
import socket			

s = socket.socket()		 

port = 1234	

s.bind(('', port))		 
print ("socket binded to %s" %(port)) 


s.listen(5)	 
print ("socket is listening")		 

while True:
    c, addr = s.accept()	 
    print ('Got connection from', addr )
    break

data = c.recv(1024).decode()
print(f"Data received {data}")
dec = des.decryption(data)
print(f"Data decrypted {dec}")
    