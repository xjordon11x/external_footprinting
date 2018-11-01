import sys
import whois
import csv
import os

output_csv=open(sys.argv[1]+"_providers_.csv","w") 
writer=csv.writer(output_csv)
dt = []

for line in open(sys.argv[2]):
	result=os.popen("whois "+line.split()[0]).read().split("\n")
#	result
	i=0
	for x in result:
#		print "X"+x
		if "Registrar:" in x  or "OrgName:" in x and i==0:
				print(line.split()[0]+" "+x)
				i=1
				dt.append([line.split()[0],x.split(":")[1]])
	if i==0:
		dt.append([line.split()[0],""])
		#except:
		#	print(line.split()[0]+" ")
#		dt.append([line.split()[0],""])

writer.writerows(dt)
