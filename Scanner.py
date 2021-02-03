import asyncio
from typing import List

from Entities.Host import Host
from Entities.NetAbstractClass import NetAbstractClass
from wrappers.NmapWCWrapper import NmapWCWrapper
from wrappers.PingWrapper import PingWrapper

def is_busy_then_close(f):
    def wrapper(*args, **kwargs):
        self = args[0]
        if self.isBusy():
            raise RuntimeWarning('Scanner already running some procces. (Please wait until it\'s finished)')
        else:
            self._busy = True
            result = f(*args, **kwargs)
            self._busy = False
            return result
    return wrapper

class Scanner():
    """(Singleton) Main class of library. It's necessary for interactions with any types of scanning."""
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Scanner, cls).__new__(cls, *args, **kwargs)
            cls.instance.__inited = False
        return cls.instance

    def __init__(self):
        if not self.__inited:
            self.__inited = True
            self._busy = False
            self.current_loop = None

    def isBusy(self):
        """Getter for checking state of scanner"""
        if self._busy:
            return True
        return False

    @is_busy_then_close
    def ping(self, scan_obj):
        """Method is synchronous provider for asynchronous function __ping.
           It's necessary for multiply ping hosts."""
        list_of_queries = asyncio.run(self.__ping(scan_obj))
        return PingWrapper(list_of_queries)

    async def __ping(self, scan_obj):
        """Corrutine method for asynchronous processing multiply ping."""
        self.sem = asyncio.Semaphore(400)
        tasks = []
        assert isinstance(scan_obj, List), 'Inside of Scanner.ping must be a List (If you need ping only some one element just wrapper it on [])'
        for element in scan_obj:
            if isinstance(element, Host):
                tasks.append(element.ping(self.sem))
            else:
                tasks.extend(await element.ping(self.sem))
        list_of_queries = []
        for task in asyncio.as_completed(tasks):
            list_of_queries.append(await task)
        return list_of_queries

    @is_busy_then_close
    def nmap_vuln_wc(self, scan_obj):
        """Method is synchronous provider for asynchronous function __nmap_vuln_wc.
           It's necessary for checking WannaCry vulerable."""
        list_of_queries = asyncio.run(self.__nmap_vuln_wc(scan_obj))
        return NmapWCWrapper(list_of_queries)

    async def __nmap_vuln_wc(self, scan_obj):
        """Corrutine method for asynchronous processing multiply checking vulnerable Wanna Cry."""
        self.sem = asyncio.Semaphore(400)
        tasks = []
        assert isinstance(scan_obj, List), 'Inside of Scanner.ping must be a List (If you need ping only some one element just wrapper it on [])'
        for element in scan_obj:
            if isinstance(element, Host):
                tasks.append(element.nmap_vuln_wc(self.sem))
            else:
                tasks.extend(await element.nmap_vuln_wc(self.sem))
            list_of_queries = []
            for task in asyncio.as_completed(tasks):
                list_of_queries.append(await task)
            return list_of_queries


