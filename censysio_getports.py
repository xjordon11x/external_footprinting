import sys
import os
import requests
import urllib2
import base64


apifile=open("api_censysio.info","r").readlines()
API_ID=apifile[0].rsplit()[0]
API_SECRET=apifile[1].rsplit()[0]
print API_ID
print API_SECRET
url="https://censys.io/api/v1/search/ipv4"


file=open("hosts.txt","r")

for ip in file :
	query_args = { 'query':ip , 'flatten':True}
#data = urllib.urlencode(query_args)
	protolist=[]
	ips=""


	API_URL = "https://www.censys.io/api/v1"
	res = requests.post(API_URL + "/search/ipv4", json = query_args, auth=(API_ID, API_SECRET))
	payload = res.json()
#	print payload

	for r in payload['results']:
		ips = r["ip"]
		protolist = r["protocols"]



	print ips
	print protolist

