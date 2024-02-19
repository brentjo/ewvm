import socket
import sys

HOST = "0.0.0.0"
PORT = $PORT

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST, PORT))
	s.listen()
	while True:
		conn, addr = s.accept()
		try:
			conn.settimeout(2)
			with conn:
				print(f"-------START from {addr}-------\n")
				while True:
					data = conn.recv(1024)
					print(str(data)[2:-1].replace("\\r\\n", "\r\n"))
					sys.stdout.flush()
					if not data:
						break
				print("-----------------------END---------------------\n")
				sys.stdout.flush()
				conn.close()
		except socket.timeout:
			print("-----------------------------------------------\n")
			sys.stdout.flush()