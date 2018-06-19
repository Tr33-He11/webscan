#!/usr/bin/env python
#coding:utf-8
# Author:zerokeeper

import re
import sys
import Queue
import threading
import optparse
import requests
import ssl
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
from IPy import IP
import time
reload(sys) 
sys.setdefaultencoding('utf-8')

printLock = threading.Semaphore(1)  #lock Screen print
TimeOut = 8  #request timeout

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36','Connection':'close'}

#ports

small_ports=[80, 443]
medium_ports=[80, 443, 8000, 8080, 8443] #default
large_ports=80, 81, 443, 591, 2082, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888, 55672
huge_ports=80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 11371, 12443, 16080, 18091, 18092, 20720, 55672

def get_ip_list(ip):
  ip_list = []
  if '.txt' in ip:
      ip_config = open(ip, 'r')
      for ip in ip_config:
          ip_list.extend(get_ip_list(ip.strip()))
      ip_config.close()
  elif re.search("[a-zA-Z]", ip):
      if "//" not in ip:
          ip_list.append(ip)
      else:
          print "target wrong format"
  else:
      ip_list=IP(ip)
  return ip_list

class scan():

  def __init__(self,host,threads_num,port,out):
    self.threads_num = threads_num
    self.host = get_ip_list(host)
    self.port = port
    self.out = out
	#build ip queue
    self.IPs = Queue.Queue()
    
    if re.search("[0-9]", self.port):
      port_list = self.port.split(',')
    elif self.port=="small":
      port_list=small_ports
    elif self.port=="medium":
      port_list=medium_ports
    elif self.port=="large":
      port_list=large_ports
    elif self.port=="huge":
      port_list=huge_ports
    # print port_list
    for ip in self.host:
      for port in port_list:
        self.IPs.put(':'.join([str(ip),str(port)]))




  def request(self):
    with threading.Lock():
      while self.IPs.qsize() > 0:
        ip = self.IPs.get()
        host,port=ip.split(':')
        try:
          if port == '443':
            url = "https://" + str(host)+"/"
          else:
              if port == '80':
                  url = "http://" + str(host)+"/"
              else:
                  url = "http://" + str(host) + ":" + str(port)+"/"
          r = requests.Session().get(url,headers=header,timeout=TimeOut,verify=False)
          status = r.status_code
          title = re.search(r'<title>(.*)</title>', r.content) #get the title
          if title:
            title = title.group(1).encode('utf-8').decode('utf-8').strip().strip("\r").strip("\n")[:30]
          else:
            title = "None"
          banner = ''
          try:
            if r.headers['Server']:
              banner += r.headers['Server'][:20] #get the server banner
            elif r.headers['X-Powered-By']:
              banner += r.headers['X-Powered-By'][:20]
          except:pass
          printLock.acquire()
          print "|%-30s|%-6s|%-20s|%-30s|" % (url,status,banner,title)
          print "+------------------------------+------+--------------------+------------------------------+"

          #Save log
          with open(self.out,'a') as f:
            data=",".join([str(url),str(status),str(banner),str(title)])
            f.write(data+"\n")

        except Exception,e:
          # print e
          printLock.acquire()
        finally:
          printLock.release()
  
  
  #Multi thread
  def run(self):
    for i in range(self.threads_num):
      t = threading.Thread(target=self.request)
      t.setDaemon(True)
      t.start()

    t_join(self.threads_num)

def t_join(m_count):
    tmp_count = 0
    i = 0
    while True:
        time.sleep(2)
        ac_count = threading.activeCount()
        if ac_count < m_count and ac_count == tmp_count:
            i += 1
        else:
            i = 0
        tmp_count = ac_count
        if ( threading.activeCount() <= 1) or i > 5:
            break

if __name__ == "__main__":
  parser = optparse.OptionParser("Usage: %prog [options] target or target.txt (support ip and domain)")
  parser.add_option("-t", "--thread", dest = "threads_num",
    default = 20, type = "int",
    help = "[optional]number of  theads,default=20")
  parser.add_option("-p", "--port", dest = "port",
    default = "medium", type = "string",
    help = "[optional]ports of tagets or choose small,medium,large,huge")
  parser.add_option("-o", "--out", dest = "out",
    default = 'report.txt', type = "string",
    help = "[optional]out file name")
  (options, args) = parser.parse_args()
  if len(args) < 1:
    parser.print_help()
    sys.exit(0)

  print "+------------------------------+------+--------------------+------------------------------+"
  print "|     URI                      |Status|       Server       |            Title             |"
  print "+------------------------------+------+--------------------+------------------------------+"

  s = scan(host=args[0],threads_num=options.threads_num,port=options.port,out=options.out)
  s.run()
