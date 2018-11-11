#xjordon11x
#Get dnsdumpster results for a given DNS
import requests
import BeautifulSoup
import requests
import re
import sys
import base64
import csv
from bs4 import BeautifulSoup

session=requests.Session()
domain=sys.argv[1]
def retrieve_results(table):
    res = []
    trs = table.findAll('tr')
    for tr in trs:
        tds = tr.findAll('td')
        pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        try:
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = str(tds[0]).split('<br/>')[0].split('>')[1]
            header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
            reverse_dns = tds[1].find('span', attrs={}).text
            additional_info = tds[2].text
            country = tds[2].find('span', attrs={}).text
            autonomous_system = additional_info.split(' ')[0]
            provider = ' '.join(additional_info.split(' ')[1:])
            provider = provider.replace(country, '')
            data = {'domain': domain,
                    'ip': ip,
                    'reverse_dns': reverse_dns,
                    'as': autonomous_system,
                    'provider': provider,
                    'country': country,
                    'header': header}
            res.append(data)
        except:
            pass
    return res
def retrieve_txt_record(table):
    res = []
    for td in table.findAll('td'):
        res.append(td.text)
    return res

dnsdumpster_url = 'https://dnsdumpster.com/'

req = session.get(dnsdumpster_url)
soup = BeautifulSoup(req.content, 'html.parser')
csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
print('Retrieved token: %s' % csrf_middleware)

cookies = {'csrftoken': csrf_middleware}
headers = {'Referer': dnsdumpster_url}
data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain}
req = session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers)

if req.status_code != 200:
#    print("Unexpected status code from {url}: {code}".format(url=dnsdumpster_url, code=req.status_code),file=sys.stderr,)
    print "RESPONSE CODE != 200" 
    exit
#   return []

if 'error' in req.content.decode('utf-8'):
    print("There was an error getting results")
    exit
 #   return []

soup = BeautifulSoup(req.content, 'html.parser')
tables = soup.findAll('table')

res = {}
res['domain'] = domain
res['dns_records'] = {}
res['dns_records']['dns'] =retrieve_results(tables[0])
res['dns_records']['mx'] = retrieve_results(tables[1])
res['dns_records']['txt'] = retrieve_txt_record(tables[2])
res['dns_records']['host'] =retrieve_results(tables[3])

print res['domain']


print "_____"

output_csv=open(sys.argv[1]+"_dnsdumpster_.csv","w") 
writer=csv.writer(output_csv)
dt = ['domain','ip','provider']
for x in res['dns_records']['host']:
	print x['domain']
	print x['ip']
	print x['provider']
	dt.append([x['domain'],x['ip'],x['provider']])

writer.writerows(dt)



