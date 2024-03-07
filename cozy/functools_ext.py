from collections.abc import Callable
from typing import TypeVar

# This module contains generic functional programming style Python functions

# Type variables for parametric polymorphic annotations
T = TypeVar('T')
U = TypeVar('U')
V = TypeVar('V')

B = TypeVar('B')
C = TypeVar('C')

# Simultaneously maps and folds over a nested Python datastructure
# in preorder traversal order
def preorder_mapfold(val0: any, f: Callable[[any, T], tuple[any, T]], accum0: T, sort=True) -> tuple[any, T]:
    """
    Simultaneously maps and folds over a nested Python datastructure in preorder traversal order. The datastructure may consist of arbitrarily nested lists, tuples, dictionaries and sets. Note that for dictionaries, both keys and values will be traversed.

    :param any val0: The datastructure to traverse.
    :param Callable[[any, T], tuple[any, T]] f: This function takes as input a value inside the datastructure, the accumulated value and should return a mapped value and newly accumulated value.
    :param T accum0: Initial accumulation parameter.
    :return: The mapped datastructure and final accumulated value.
    :rtype: tuple[any, T]
    """
    (val1, accum1) = f(val0, accum0)
    if isinstance(val1, list):
        ret = []
        accum2 = accum1
        for elem0 in val1:
            (elem1, accum3) = preorder_mapfold(elem0, f, accum2, sort=sort)
            ret.append(elem1)
            accum2 = accum3
        return (ret, accum2)
    elif isinstance(val1, tuple):
        ret_lst = []
        val1_lst = list(val1)
        accum2 = accum1
        for elem0 in val1_lst:
            (elem1, accum3) = preorder_mapfold(elem0, f, accum2, sort=sort)
            ret_lst.append(elem1)
            accum2 = accum3
        return (tuple(ret_lst), accum2)
    elif isinstance(val1, dict):
        if sort:
            ordered_keys = sorted(val1.keys())
        else:
            ordered_keys = val1.keys()
        ret = dict()
        accum2 = accum1
        for k0 in ordered_keys:
            (k1, accum3) = preorder_mapfold(k0, f, accum2, sort=sort)
            elem0 = val1[k0]
            (elem1, accum4) = preorder_mapfold(elem0, f, accum3, sort=sort)
            ret[k1] = elem1
            accum2 = accum4
        return (ret, accum2)
    elif isinstance(val1, set):
        if sort:
            ordered_elems = sorted(list(val1))
        else:
            ordered_elems = val1
        ret = set()
        accum2 = accum1
        for elem0 in ordered_elems:
            (elem1, accum3) = preorder_mapfold(elem0, f, accum2, sort=sort)
            ret.add(elem1)
            accum2 = accum3
        return (ret, accum2)
    else:
        return (val1, accum1)

def preorder_fold(val0: any, f: Callable[[any, U], U], accum0: U) -> U:
    """
    Folds over a Python datastructure in preorder traversal. The datastructure may consist of arbitrarily nested lists, tuples, dictionaries and sets. Note that for dictionaries, both keys and values will be traversed.

    :param any val0: The datastructure to traverse.
    :param Callable[[any, U], U] f: This function takes as input the value inside the datastructure, the accumulated value and should return a new accumulated value.
    :param U accum0: Initial accumulation parameter.
    :return: The final accumulated value.
    :rtype: U
    """
    def g(val1, accum1):
        return (val1, f(val1, accum1))

    (val2, accum2) = preorder_mapfold(val0, g, accum0)
    return accum2

def fmap(val0: any, f: Callable[[any], any]) -> any:
    """
    Maps a Python datastructure. The datastructure may consist of arbitrarily nested lists, tuples, dictionaries and sets.

    :param any val0: The datastructure to map. Note that for dictionaries, both keys and values will be mapped.
    :return: The mapped datastructure.
    :rtype: any
    """
    def g(val1, accum1):
        return (f(val1), accum1)

    (val2, accum2) = preorder_mapfold(val0, g, None, sort=False)
    return val2

def compose(f: Callable[[B], C], g: Callable[[...], B]) -> Callable[[...], C]:
    """
    Composes two functions, `f` and `g`, to create a new function h(\*a, \*\*kw) = f(g(\*a, \*\*kw))

    :param Callable[[B], C] f: The first function to compose.
    :param Callable[[...], B] g: The second function to compose.
    :return: A newly composed function which takes in an arbitrary number of arguments and keyword arguments, and returns a C.
    :rtype: Callable[[...], C]
    """
    return lambda *a, **kw: f(g(*a, **kw))