import asyncio

from Entities.NetAbstractClass import NetAbstractClass


class Host(NetAbstractClass):
    """This class is a wrapper of ipv4 address. It's save last states of any scanning."""
    OS_UNKNOWN = 'unknown'
    OS_WINDOWS = 'windows'
    OS_LINUX = 'linux'
    OS_ANY = 'any'

    def __init__(self, ip, ttl=None):
        self.ip = ip
        self.ttl = ttl
        self.os = 'unknown'
        self.active = False
        self.vuln_wc = False

    def set_ttl(self, value):
        """Setter ttl host in last scanning"""
        assert isinstance(value, int) or value is None, 'Host.set_ttl: wrong argument "value".'
        self.ttl = value
        self.os = self.define_os(value)

    def set_vuln(self, type, value):
        """Setter flags vulnerable of host"""
        if type == 'wc' and value is True: self.vuln_wc = True

    def define_os(self, ttl):
        """Method, which return operation system by inner data of host (Now, by ttl)"""
        if ttl == None:
            return Host.OS_UNKNOWN
        if ttl < 100:
            return Host.OS_LINUX
        elif ttl < 200:
            return Host.OS_WINDOWS
        else:
            return Host.OS_ANY

    def __repr__(self):
        return f'<Host: {self.ip}>'

    async def ping(self, sem):
        """Corrutine method, which doing ping host in new procces(shell) and get only string with success ping.
        If hosts unacsessable then function return (ip, self, None),
        else function return (ip, self, stdout<one string with success request>)"""
        cmd = f'ping -c 3 -i 1 {str(self.ip)} | grep ttl | sed -n \'$p\''
        async with sem:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if stdout:
                stdout = stdout.decode()
                if stdout:
                    self.active = True
                    return self.ip, self, stdout
            self.active = False
            return self.ip, self, None

    async def nmap_vuln_wc(self, sem):
        """Corrutine method, which run separate nmap shell proccess(shell) and get only string with "State: VULNERABLE".
        Host must have self.os == Host.OS_WINDOWS and self.active == True,
        If vulnerable was detected then returns (ip, self, True) else (ip, self, False)"""
        if self.active and self.os == Host.OS_WINDOWS:
            cmd = f'nmap -p445 --open -d 5 --script smb-vuln-ms17-010.nse {self.ip} | grep -e "State: VULNERABLE"'
            async with sem:
                proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE,
                                                             stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                if stdout:
                    stdout = stdout.decode()
                    if stdout:
                        return self.ip, self, True
                return self.ip, self, False
        else:
            return self.ip, self, False