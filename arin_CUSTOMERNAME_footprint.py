import ssl
from BeautifulSoup import BeautifulSoup as BS
import urllib2
import re
import requests
import sys
import csv

if len(sys.argv) < 2:
	print("_____________SOMETHING WENT WRONG :(_____________")
	print("_________________________________________________")
	print("EXAMPLE: python arin_CUSTOMERNAME_footprint.py \"GOOGLE\" ")
	print("This will do an advanced ARIN CUSTOMER Search for GOOGLE and print CIDR,IP RANGE,CUSTOMER NAME to GOOGLE_arin_.csv")
	print("_________________________________________________")
	print("_________________________________________________")
	exit()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

data=[]
links=[]
i=0
search="*"+sys.argv[1]+"*"

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}
data = [
  ('advanced', 'true'),
  ('q', search),
  ('r', 'CUSTOMER'),
  ('CUSTOMER', 'name'),
]

response = requests.post('https://whois.arin.net/ui/query.do',
headers=headers, data=data, verify=False)
#print response.content
resz=BS(response.content)
companies=resz.findAll('td')
#.findAll('a')
for td in companies:
            lnk=td.findAll('a')[0]
            link=lnk.get('href')
            print(re.sub("\n+", ",", td.text.lstrip() ) )
            ans=raw_input("This one? (y|n)")
            if ans=="y":
                    links.append(link)

output_csv=open(sys.argv[1]+"_arin_.csv","w") 
writer=csv.writer(output_csv)
for x in links:
#       print ("LINK-->",x)
        html=urllib2.urlopen(x,context=ctx)
        soup=BS(html)
#       print soup
        aa=soup.findAll('netref')
        for y in aa:
                network_url=y.text.lstrip()
#                print network_url
                html2=urllib2.urlopen(network_url+".html",context=ctx)
                tds=BS(html2).findAll('td')

		company= " ".join( tds[15].text.lstrip().split())
                data.append([tds[3].text.lstrip(),tds[1].text.lstrip(),company])
#                writer.writerows(data)
writer.writerows(data)
#print data
#       print aa
#        netlnks=lnk.get('href')
#       print (netlnks,"AAAA")
