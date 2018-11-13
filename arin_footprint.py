#xjordon11x
#Used to quickly create a external footprint from ARIN,APNIC,AFRINIC,RIPE and output to csv
#Gets CIDR,IP_Range,Netname,Registry Source
#LACNIC not working correctly
import netaddr
import re,csv,urllib2,ssl
from bs4 import BeautifulSoup as BS
import argparse
import requests
import os
import sys
import socket
import random
from multiprocessing.dummy import Pool as ThreadPool
import threading
from tabulate import tabulate
from prettytable import PrettyTable
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class Main():
    ARIN_URL='https://whois.arin.net/ui/query.do'
    removals=[]
    companies=[]
    final_data=[]
    prox=""
    red='\033[91m'
    FNTEND='\033[0m'
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'



    def __init__(self):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        parser = argparse.ArgumentParser(description='Passive Service Discovery Search')
        parser.add_argument('-c', '--client', help='Name of client', required=True)

        #output = parser.add_mutually_exclusive_group(required=True)
        parser.add_argument('-oC', '--outputcsv',required=True,default=False, help='Outputs into a .csv file')
        parser.add_argument('-oS', '--outputstandard',default=False,action='store_true',help="Prints results to a table in STDOUT")
        registries = parser.add_mutually_exclusive_group(required=True)
        registries.add_argument('-wA', '--all',default=False,action='store_true',help='Search All Registries (ARIN,RIPE,APNIC,AFRINIC')
        registries.add_argument('-wAr', '--arin',default=False,action='store_true',help='Search ARIN')
        registries.add_argument('-wAf', '--afrinic',default=False,action='store_true',help='Search AFRINIC')
        registries.add_argument('-wAp', '--apnic',default=False,action='store_true',help='Search APNIC')
        registries.add_argument('-wR', '--ripe',default=False,action='store_true',help='Search RIPE')
      #  registries.add_argument('-wL', '--lacnic',default=False,action='store_true',help='Search LACNIC')
       
       # parser.add_argument('-p', '--proxy', default=False, help='Specify SOCKS5 proxy (i.e. 127.0.0.1:8123)')
        
        parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Output in verbose mode while script runs')
        # threads plz
        #parser.add_argument('-T', '--threads', default=1, help='Specify how many threads to use. [Default = 1]')
 
        args = parser.parse_args()
        print(args)
        self.output_csv=args.outputcsv
        self.verbose=args.verbose
 
        """ if(args.proxy is not False):
            self.prox= {
                'http':'socks5://%s'% args.proxy,
                'https':'socks5://%s' %args.proxy
            }
            prxy=urllib2.ProxyHandler(self.prox)
            auth = urllib2.HTTPBasicAuthHandler()
            opener = urllib2.build_opener(prxy, auth, urllib2.HTTPHandler)
            urllib2.install_opener(opener)"""
        client_name=args.client
        if args.all:
            self.arin_search(client_name)
            self.apnic_search(client_name)
            self.ripe_search(client_name)
            self.afrinic_search(client_name)
        elif args.arin:
            self.arin_search(client_name)
        elif args.apnic:
            self.apnic_search(client_name)
        elif args.ripe:
            self.ripe_search(client_name)
        elif args.afrinic:
            self.afrinic_search(client_name)
        #elif args.lacnic:
        #    self.lacnic_search(client_name)
        if args.outputstandard:
            self.print_to_std()
        self.print_to_file()
 
            
    def get_inputs(self,length):
        remz=raw_input("Please enter the number of companies which you do"+self.BOLD+self.red+" NOT "+self.FNTEND +"want results for (Multi value use a comma to separate)\n")
        try:
            if len(remz)!=0 :
                if isinstance(remz,int)==True:
                    remz=[remz]
                else:
                    remz=remz.split(",")
                #print remz
                larger=self.checkz(remz,length,0)
                smaller=self.checkz(remz,length,1)
                
                if larger==True:
                    print("\n" +self.red+ "ERROR: Not a valid selection, a value is to large"+self.FNTEND+"\n")
                    return False
                elif smaller==True:
                    print("\n" +self.red+ "ERROR: Not a valid selection, a value is to small"+self.FNTEND+"\n")
                    return False
                else:
                    for x in remz:
                        self.removals.append(self.companies[int(x)])
                    return True
        except:
            print("\n" +self.red+ "ERROR: Incorrect input given. Should be a single number,list of numbers separated by a comma, or hit enter (for all)."+self.FNTEND+"\n")
            return False
        return True

    def checkz(self,list1,length,chk):
        rez=False
        #print list1
        try:
            if chk==0:
                for x in list1:
                    if int(x)>=int(length) and int(x)!=0:
                        rez=True
            elif chk==1:
                for x in list1:
                    if int(x)<=int(length) and int(x)!=0:
                        rez=True
        except:
            return False    
        return rez

    def print_to_file(self):
        outputcsv=open(self.output_csv+".csv","w") 
        writer=csv.writer(outputcsv)
        writer.writerows(self.final_data)
        print self.GREEN+"RESULTS WRITTEN TO "+self.output_csv+".csv"+self.FNTEND

    def arin_search(self,client):
        added=False
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        inputs_correct=False
        search="*"+client+"*"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = [
          ('advanced', 'true'),
          ('q', search),
          ('r', 'CUSTOMER'),
          ('CUSTOMER', 'name'),
        ]
        #response = requests.post(self.ARIN_URL,headers=headers, data=data, verify=False)
        #if self.prox:
        #    response = requests.post('https://whois.arin.net/ui/query.do',headers=headers, data=data, verify=False)
        #else:
        response = requests.post('https://whois.arin.net/ui/query.do',headers=headers, data=data, verify=False)
        res_content=BS(response.content,'html.parser')
        
        self.companies=res_content.findAll('td')
        num=0
            #t = PrettyTable(['Number', 'Name'])
            #for num in range(0,len(self.companies)):
            #    t.add_row([num,re.sub("\n+", ",", self.companies[num].text.lstrip())])    
                    #lnk=td.findAll('a')[0].get('href')
                    #print tabulate([str(num),re.sub("\n+", ",", self.companies[num].text.lstrip())])
                    
            # print (t)
            #while (inputs_correct==False):
            #    inputs_correct=self.get_inputs(len(self.companies))

            #remove the unwanted results from company list
            #for remz in self.removals:
            #    self.companies.remove(remz)

            #print self.companies

            #go through each company and get network information
        print("\nSearching through ARIN:")
        for x in self.companies:
            print ("\tARIN: "+self.CYAN+"[+] "+self.FNTEND+self.CYAN+re.sub("\n+", ",", x.text.lstrip())+self.FNTEND)
            link=x.findAll('a')[0].get('href')
            #print links

            html=urllib2.urlopen(link,context=ctx)
            netlinks=BS(html,'html.parser').findAll('netref')
            for net in netlinks:
                net_url=net.text.lstrip()
                html2=urllib2.urlopen(net_url+'.html',context=ctx)
                tds=BS(html2,'html.parser').findAll('td')
                company_name=" ".join(tds[15].text.lstrip().split())
                cidr=tds[3].text.rstrip("\n")
                ip_range=tds[1].text.lstrip()
                if self.verbose:
                    print("\t    CIDR:"+cidr+"\n\t    IP RANGE:"+ip_range)
                self.final_data.append([cidr,ip_range,company_name,"ARIN"])
                added=True
        if added==False:
            print self.YELLOW+"\tNo resutls found in ARIN Registry"+self.FNTEND
        print("\n")

        

    def apnic_search(self,client):
        added=False
        print("Searching through APNIC")
        resp=requests.get("https://wq.apnic.net/query?searchtext="+client,verify=False)
        parsed_json=resp.json()
        ip_range=""
        netname=""
        desc=""
        entry=[]
        for jsonobj in parsed_json:
            try:
                if jsonobj['objectType'] == "inetnum":
                    for attribute in jsonobj['attributes']:
                        if attribute['name'] in 'inetnum':
                            ip_range=attribute['values'][0]
                        if attribute['name'] in 'netname':
                            netname=attribute['values'][0]
                        if attribute['name'] in 'descr':
                            desc=attribute['values'][0]
                    if desc:
                        print ("\tAPNIC: "+self.CYAN+"[+] "+self.FNTEND+self.CYAN+" "+desc+self.FNTEND)
                        netname=desc
                    else:
                        print ("\tAPNIC: "+self.CYAN+"[+] "+self.FNTEND+self.CYAN+netname+self.FNTEND)
                    cidrip=ip_range.split("-")
                    cidrs = netaddr.iprange_to_cidrs(cidrip[0].lstrip(), cidrip[1].lstrip())


                    self.final_data.append([str(cidrs[0]),ip_range,netname,"APNIC"])
                    added=True
            except Exception as e:
                continue
        if added==False:
            print self.YELLOW+"\tNo resutls found in APNIC Registry"+self.FNTEND
        print("\n")


    def ripe_search(self,client):
        added=False
        ip_range=""
        netname=""
        entry=[]
        desc=""
        print("\nSearching through RIPE")
        try:
            resp=requests.get("https://apps.db.ripe.net/db-web-ui/api/whois/search?abuse-contact=true&flags=B&ignore404=true&managed-attributes=true&query-string="+client+"&resource-holder=true",verify=False)
            #print resp.content
            
            parsed_json=resp.json()
            #print parsed_json
            for obj in parsed_json['objects']['object']:
                if obj['type'] in 'inetnum':
                    for attribute in obj['attributes']['attribute']:
                        if attribute['name'] in 'inetnum':
                            ip_range=attribute['value']
                        if attribute['name'] in 'netname':
                            netname=attribute['value']
                        if attribute['name'] in 'descr' and client in attribute['value']:
                            desc=attribute['value']
                    if desc:
                        print ("\tRIPE: "+self.CYAN+"[+] "+self.FNTEND+self.CYAN+" "+desc+self.FNTEND)
                        netname=desc
                    else:
                        print ("\tRIPE: "+self.CYAN+"[+] "+self.FNTEND+self.CYAN+netname+self.FNTEND)
                    cidrip=ip_range.split("-")
                    cidrs = netaddr.iprange_to_cidrs(cidrip[0].lstrip(), cidrip[1].lstrip())

                    self.final_data.append([str(cidrs[0]),ip_range,netname,"RIPE"])
                    added=True
            #print (entry)
        except Exception as e:
            pass
        if added==False:
            print self.YELLOW+"\tNo resutls found in RIPE Registry"+self.FNTEND
        print("\n")

    def afrinic_search(self,client):
        added=False
        print("\nSearching through AFRINIC")
        dt={'key':client,'sourceDatabases':'afrinic','tabs':'on'}
        resp=requests.post('https://www.afrinic.net/whois-web/public/?lang=en',data=dt,verify=False)
        pre=BS(resp.content,'html.parser').find_all('pre')
        for x in pre:
            ip_range=""
            netname=""
            ip6_range=""
            ip6_cidr=""
            for y in x.text.split("\n"):
                y=re.sub("\:(\s+)", "^", y)
                if 'inetnum' in y:
                    ip_range=y.split("^")[1]
                if 'inet6num' in y:
                    ip6_cidr=y.split("^")[1]
                if 'netname' in y:
                    netname=y.split("^")[1]
            
            if netname!="":
                print ("\tAFRINIC: "+self.CYAN+"[+] "+self.FNTEND+self.CYAN+netname+self.FNTEND)
                if ip6_cidr !="":
                    ip6_range=str(netaddr.IPNetwork(ip6_cidr).ipv6().network)+" - "+str(netaddr.IPNetwork(ip6_cidr).ipv6().broadcast)
                    #print str(ip6_range)
                    self.final_data.append([str(ip6_cidr),ip6_range,netname,'AFRINIC'])
                    added=True
                if ip_range !="":
                    cidrip=ip_range.split("-")
                    cidrs = netaddr.iprange_to_cidrs(cidrip[0].lstrip(), cidrip[1].lstrip())
                    self.final_data.append([str(cidrs[0]),ip_range,netname,'AFRINIC'])
                    added=True
        if added==False:
            print self.YELLOW+"\tNo resutls found in AFRINIC Registry"+self.FNTEND
        print("\n")

                   
    def print_to_std(self):
        t = PrettyTable(['Number', 'CIDR','IP Range','Net Name', 'Source'])
        for num in range(0,len(self.final_data)):
            t.add_row([num,self.final_data[num][0],self.final_data[num][1],self.final_data[num][2],self.final_data[num][3]])
            #    t.add_row([num,re.sub("\n+", ",", self.companies[num].text.lstrip())])    
                    #lnk=td.findAll('a')[0].get('href')
                    #print tabulate([str(num),re.sub("\n+", ",", self.companies[num].text.lstrip())]) 
        print t

if __name__ == "__main__":
    try:
        combined_results = {}  # Dict to consolidate host and port results from all modules
        Main()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()

