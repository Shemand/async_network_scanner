import ipaddress
from typing import List, Dict

from Entities.Host import Host
from Entities.NetAbstractClass import NetAbstractClass
from Entities.SubNetwork import SubNetwork

class Network(NetAbstractClass):
    """Class for a designation and aggregate all SubNetworks, which described in 'networks.list'.

    hosts -- the all hosts from all subnetworks of network type<{ip : Host}>
    sub_networks -- the sub networks of network type<{network_address : SubNetwork}>

    """
    def __init__(self):
        self.__file_name = 'networks.list'
        self.__initialize_networks(self.read_file())
        self.hosts = self.__get_all_hosts()

    def read_file(self):
        """Read file of network which specified in variable self.__file_name.
        Return [str]"""
        subnetworks = []
        with open(self.__file_name, 'r') as file:
            for line in file:
                address_str = line.removesuffix('\n')
                subnetworks.append(address_str)
        return subnetworks

    def __initialize_networks(self, sub_networks):
        """Method initialize subnetworks of Network by using class SubNetwork.
        After use this function self.sub_netoworks will filled."""
        self.sub_networks = {}
        for address in sub_networks:
            self.sub_networks[address] = SubNetwork(address)

    def __get_all_hosts(self):
        """Method filling self.hosts of Network by using pass through of all SubNetwork.
        After use this function self.hosts will filled."""
        hosts = {}
        for address in self.sub_networks:
            for host_ip in self.sub_networks[address].hosts:
                hosts[host_ip] = self.sub_networks[address].hosts[host_ip]
        return hosts

    async def ping(self, sem):
        """Creating corrutines of SubNetwork.ping and combines them in array. Return [Corrutine]"""
        pinged_subnetworks = []
        for network_address in self.sub_networks:
            pinged_subnetworks.extend(await self.sub_networks[network_address].ping(sem))
        return pinged_subnetworks

    async def nmap_vuln_wc(self, sem):
        """Creating corrutines of SubNetwork.nmap_vuln_wc and combines them in array. Return [Corrutine]"""
        nmaped_subnetworks = []
        for network_address in self.sub_networks:
            nmaped_subnetworks.extend(await self.sub_networks[network_address].nmap_vuln_wc(sem))
        return nmaped_subnetworks
