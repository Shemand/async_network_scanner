import time

from Entities.Host import Host
from Entities.Network import Network
from Entities.SubNetwork import SubNetwork
from Scanner import Scanner

if __name__ == '__main__':
   network = Network()
   scanner = Scanner()
   start = time.time()
   z = scanner.ping([network]).update_ttl()
   l = scanner.nmap_vuln_wc([network]).filter_vulnerable().as_dict()
   executing_time = time.time() - start
   print(f'time of executing: {executing_time}')
   print(l)