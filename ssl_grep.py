import os,sys
import csv
host=""
sslv3=[]
sha1=[]
tlsv1=[]
rc4=[]

#INPUT SSL_SCAN.NMAP and will quickly sort out into 

if len(sys.argv) < 2:
	print("***************************")
	print("NEED TO INPUT SSL_SCAN.NMAP")
	print("***************************")
	sys.exit(0)
else:
	for x in range(1,(len(sys.argv))):
		with open(sys.argv[x]) as f:
			for x in f.readlines():
				if "Nmap scan report" in x:
					host=""
					host=x.split(" ")[4]
					print(host)
				if "V3" in x.upper():
					if host not in sslv3:
						sslv3.append(host)
						#print("SSLV3")
				if "SHA-1" in x.upper():
					if host not in sha1:	
						sha1.append(host)
						#print("SHA1")
				if "1.0:" in x.upper():
					if host not in tlsv1:
						tlsv1.append(host)
						#print("TLSV1")
				if "RC4" in x.upper():
					if host not in rc4:
						rc4.append(host)
						#print("RC4")


wtr = open ('rc4.txt', 'w+')
for x in rc4 : wtr.write(x)

wtr = open ('ssl3.txt', 'w+')
for x in sslv3 : wtr.write (x)

wtr = open ('tls1.txt', 'w+')
for x in tlsv1 : wtr.write (x)

wtr = open ('sha1.txt', 'w+')
for x in sha1 : wtr.write (x)


print(sslv3)
print(tlsv1)
print(sha1)
print(rc4)
