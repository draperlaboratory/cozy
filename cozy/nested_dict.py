from typing import TypeVar, Generic, Callable

A = TypeVar('A')
B = TypeVar('B')

def _insert_path(d: dict, path: tuple[str | int, ...], value):
    if len(path) == 0:
        raise ValueError("Inserting a path of length 0")
    else:
        key = path[0]
        if len(path) == 1:
            d[key] = value
        else:
            if key not in d:
                d[key] = dict()
            _insert_path(d[key], path[1:], value)

class NestedDict(Generic[A]):
    """
    A nested dict is an arbitrarily nested Python dict holding values on the leaves. The keys of the dictionaries\
    must be str or int values. Note that NestedDict objects should not contain NestedDict objects within their\
    data dictionary. In other words, NestedDict is a wrapper for a dict, and does not nest inside itself.
    """
    def __init__(self, data: dict):
        self.data = data

    @staticmethod
    def empty() -> 'NestedDict':
        return NestedDict(dict())

    def __setitem__(self, key: tuple[str | int, ...], value):
        _insert_path(self.data, key, value)

    def paths(self) -> set[tuple[str | int, ...]]:
        """
        Computes the set of all possible paths through the annotation
        """
        ret: set[tuple[str | int, ...]] = set()
        def walk(d: dict, path: tuple[str | int, ...]):
            if isinstance(d, dict):
                for (k, v) in d.items():
                    walk(v, path + (k,))
            else:
                ret.add(path)
        walk(self.data, tuple())
        return ret

    def filter(self, paths: set[tuple[str | int, ...]]) -> 'NestedDict[A]':
        """
        Returns a copy of the current dict, filtered so that only leaves that contain a path in the paths\
        set are returned.
        """
        def walk(d, p):
            if isinstance(d, dict):
                ret = dict()
                for (k, v) in d.items():
                    rec_val = walk(v, p + (k,))
                    if rec_val is not None:
                        ret[k] = rec_val
                if len(ret) > 0:
                    return ret
                else:
                    return None
            else:
                if p in paths:
                    return d
                else:
                    return None
        ret = walk(self.data, tuple())
        if ret is None:
            ret = dict()
        return NestedDict(ret)

    def map(self, f: Callable[[A], B]) -> 'NestedDict[B]':
        def walk(d):
            if isinstance(d, dict):
                return {k: walk(v) for (k, v) in d.items()}
            else:
                return f(d)
        return NestedDict(walk(self.data))
