from Entities.Host import Host
from wrappers.ActionWrapperAbstract import ActionWrapperAbstract, is_empty_then_close


class NmapWCWrapper(ActionWrapperAbstract):
    """Class-wrapper is result work of method Scanner.nmap_vuln_wc"""
    def __init__(self, list_of_queries):
        super().__init__(list_of_queries)
        # flags
        self._cleaned = False

    @is_empty_then_close
    def clear_empty(self):
        """(Not pure method. Changing state of self.list_of_queries)
        Method, which filter tuples of List (self.list_of_queries) and remove hosts without os"""
        if not self._cleaned:
            index = 0
            while index < len(self.list_of_queries):
                ip, host, is_vuln = self.list_of_queries[index]
                if host.os != 'unknown':
                    index += 1
                    continue
                self.list_of_queries.pop(index)
            self._cleaned = False
        return self

    @is_empty_then_close
    def update_wc_vuln(self):
        """Method, which passes through self.list_of_queries,
        and extract from each Host and assign him wc flag according to tuple"""
        for ip, host, is_vuln in self.list_of_queries:
            host.set_vuln('wc', is_vuln)
        return self

    @is_empty_then_close
    def filter_vulnerable(self):
        """(Not pure method. Changing state of self.list_of_queries)
        Method, which filter tuples of List (self.list_of_queries) and remove hosts without WannaCry vulnerable"""
        self.list_of_queries = list(filter(lambda x: x[2] is True, self.list_of_queries))
        return self

    def as_dict(self):
        """Method which return self.list_of_queries like a dictionary in format [ip] = (Host, wc_flag)"""
        self.clear_empty()
        to_return = {}
        for ip, host, is_vuln in self.list_of_queries:
            if ip in to_return:
                if to_return[ip][0].os == Host.OS_UNKNOWN and host.os != Host.OS_UNKNOWN:
                    to_return[ip] = (host, is_vuln)
            else:
                to_return[ip] = (host, is_vuln)
        return to_return

    def as_list_of_tuples(self):
        """Method which return self.list_of_queries in format (ip, Host, wc_flag)"""
        return self.list_of_queries
