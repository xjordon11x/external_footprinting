#xjordon11x
#Used to quickly create a external footprint from ARIN.NET results
from netaddr import *
import re,csv,urllib2,ssl
from BeautifulSoup import BeautifulSoup as BS
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
#from termcolor import colored


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

    def __init__(self):
        parser = argparse.ArgumentParser(description='Passive Service Discovery Search')
        parser.add_argument('-c', '--client', help='Name of client', required=True)
#	searchinput = parser.add_mutually_exclusive_group(required=True)
	#maininput=parser.add_argument_group('Search Type')
 #       searchinput.add_argument('-sN', '--searchnetwork', default=False ,help='ARIN Advanced Search on Network field, ex: 192.168.1.1 or NET-64-124-0-0-1 ')
  #      searchinput.add_argument('-sC', '--searchcustomer', default=False ,help='ARIN Advanced Search on Customer field, Will add wildcard character (*) to the end of each customer name ')
        output = parser.add_mutually_exclusive_group(required=True)
 #       output.add_argument('-oA', '--outputall', default=False, help='Outputs in all available formats')
  #      output.add_argument('-oS', '--outputstandard', default=False, help='Outputs standard output to a .log file')
        output.add_argument('-oC', '--outputcsv', default=False, help='Outputs into a .csv file')


        # adding proxy option to test within PwC offices (Shodan cert not trusted by PwC)
       # parser.add_argument('-p', '--proxy', default=False, help='Specify SOCKS5 proxy (i.e. 127.0.0.1:8123)')
        # adding proxy option to test within PwC offices (Shodan cert not trusted by PwC)
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

        self.arin_search(args.client)
 
            
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

    def arin_search(self,client):
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
        res_content=BS(response.content)
        
        self.companies=res_content.findAll('td')
        num=0
        t = PrettyTable(['Number', 'Name'])
        for num in range(0,len(self.companies)):
            t.add_row([num,re.sub("\n+", ",", self.companies[num].text.lstrip())])    
                #lnk=td.findAll('a')[0].get('href')
                #print tabulate([str(num),re.sub("\n+", ",", self.companies[num].text.lstrip())])
                
        print (t)
        while (inputs_correct==False):
            inputs_correct=self.get_inputs(len(self.companies))

        #remove the unwanted results from company list
        for remz in self.removals:
            self.companies.remove(remz)

        #print self.companies

        #go through each company and get network information
        print("Getting Network Info For:")
        for x in self.companies:
            print ("\t"+self.GREEN+"[+] "+self.FNTEND+self.GREEN+re.sub("\n+", ",", x.text.lstrip())+self.FNTEND)
            link=x.findAll('a')[0].get('href')
            #print links

            html=urllib2.urlopen(link,context=ctx)
            netlinks=BS(html).findAll('netref')
            for net in netlinks:
                net_url=net.text.lstrip()
                html2=urllib2.urlopen(net_url+'.html',context=ctx)
                tds=BS(html2).findAll('td')
                company_name=" ".join(tds[15].text.lstrip().split())
                cidr=tds[3].text.lstrip()
                ip_range=tds[1].text.lstrip()
                if self.verbose:
                    print("\t    CIDR:"+cidr+"\n\t    IP RANGE:"+ip_range)
                self.final_data.append([cidr,ip_range,company_name])

        self.print_to_file()

        





if __name__ == "__main__":
    try:
        combined_results = {}  # Dict to consolidate host and port results from all modules
        Main()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()

