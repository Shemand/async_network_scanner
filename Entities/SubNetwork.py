import ipaddress

from Entities.Host import Host
from Entities.NetAbstractClass import NetAbstractClass


class SubNetwork(NetAbstractClass):
    """This class represent and aggregate many hosts of one network with some address (like 192.168.0.0/24)"""
    def __init__(self, network_address):
        self.hosts = {}
        self.__initialize_networks(network_address)

    def __initialize_networks(self, network_address):
        """This protected method necessary for initializing self.hosts[ip] = [Host] of class"""
        self.hosts = {}
        addresses = ipaddress.ip_network(network_address)
        for ip in addresses:
            self.hosts[str(ip)] = Host(str(ip))

    async def ping(self, sem):
        """Corrutine method, which creating list corrutines for asynchronous multly pings of hosts"""
        pinged_hosts = []
        for ip in self.hosts:
            pinged_hosts.append(self.hosts[ip].ping(sem))
        return pinged_hosts

    async def nmap_vuln_wc(self, sem):
        """Corrutine method for asynchronous processing multiply checking hosts vulnerable Wanna Cry."""
        nmapped_hosts = []
        for ip in self.hosts:
            nmapped_hosts.append(self.hosts[ip].nmap_vuln_wc(sem))
        return nmapped_hosts
