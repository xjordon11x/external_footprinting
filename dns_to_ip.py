#xjordon11x
#get ip address from a DNS Hostname
import socket
import sys

for line in open(sys.argv[1]):
	try:
		addr1 = socket.gethostbyname(line.split()[0])
		print line.split()[0]+","+addr1
	except:
		print line.split()[0]+", "

