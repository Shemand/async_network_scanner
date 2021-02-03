class ActionWrapperAbstract():
   """This abstract class necessary for aggregate any wrappers by one parent class

   Wrappers of actions necessary for creating usability design for manipulating with any data,
   which returns by any actions (like "ping") of class Scanner

   """
    def __init__(self, list_of_queries):
        self.list_of_queries = list_of_queries
        if list_of_queries == []:
            self._empty = True
        else:
            self._empty = False


def is_empty_then_close(f):
    """Decorator, which necessary for checking of empty wrapper."""
    def wrapper(*args, **kwargs):
        self = args[0]
        if self._empty:
            return self
        else:
            return f(*args, **kwargs)
    return wrapper
