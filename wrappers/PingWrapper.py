from wrappers.ActionWrapperAbstract import ActionWrapperAbstract, is_empty_then_close


class PingWrapper(ActionWrapperAbstract):
    """Class-wrapper is result work of method Scanner.ping"""
    def __init__(self, list_of_queries):
        super().__init__(list_of_queries)
        # flags
        self._cleaned_empty = False
        self._extracted_ttl = False

    @is_empty_then_close
    def clear_empty(self):
        """Method for filter inactive hosts from self.list_of_queries"""
        if not self._cleaned_empty:
            index = 0
            while index < len(self.list_of_queries):
                ip, host, response = self.list_of_queries[index]
                if response is not None:
                    index += 1
                    continue
                self.list_of_queries.pop(index)
            self._cleaned_empty = False
        return self

    @is_empty_then_close
    def extract_ttl(self):
        """(Not pure method, changing state of self.list_of_queries)
        Method, which changing response of tuple self.list_of_queries : (ip, Host, response)
        and extract from response ttl and write it like int."""
        if not self._extracted_ttl:
            self._extracted_ttl = True
            self.clear_empty()
            index = 0
            while index < len(self.list_of_queries):
                ip, host, response = self.list_of_queries[index]
                if 'ttl' in response:
                    start = response.index('ttl')
                    end = response.index(' ', start)
                    response = int(str(response[start:end].split('=')[1]))
                self.list_of_queries[index] = ip, host, response
                index += 1
        return self

    @is_empty_then_close
    def update_ttl(self):
        """Method, which passes through self.list_of_queries,
        and extract from each Host and assign him ttl from tuple"""
        if not self._extracted_ttl:
            self.extract_ttl()
        for ip, host, ttl in self.list_of_queries:
            host.set_ttl(ttl)
        return self

    def as_dict(self):
        """Method, which form self.list_of_queries in dictionary with form list [ip] = (Host, response)"""
        self.clear_empty()
        to_return = {}
        for ip, host, response in self.list_of_queries:
            if ip in to_return:
                if to_return[ip][1] is None and response is not None:
                    to_return[ip] = (host, response)
            else:
                to_return[ip] = (host, response)
        return to_return

    def as_list_of_tuples(self):
        """Method, return data like a List of tuple (ip, Host, response)"""
        return self.list_of_queries
