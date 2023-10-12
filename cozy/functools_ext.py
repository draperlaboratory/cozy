# This module contains generic functional programming style Python functions

# Simultaneously maps and folds over a nested Python datastructure
# in preorder traversal order
def preorder_mapfold(val0, f, accum0):
    (val1, accum1) = f(val0, accum0)
    if isinstance(val1, list):
        ret = []
        accum2 = accum1
        for elem0 in val1:
            (elem1, accum3) = preorder_mapfold(elem0, f, accum2)
            ret.append(elem1)
            accum2 = accum3
        return (ret, accum2)
    elif isinstance(val1, tuple):
        ret_lst = []
        val1_lst = list(val1)
        accum2 = accum1
        for elem0 in val1_lst:
            (elem1, accum3) = preorder_mapfold(elem0, f, accum2)
            ret_lst.append(elem1)
            accum2 = accum3
        return (tuple(ret_lst), accum2)
    elif isinstance(val1, dict):
        ordered_keys = sorted(val1.keys())
        ret = dict()
        accum2 = accum1
        for k0 in ordered_keys:
            (k1, accum3) = preorder_mapfold(k0, f, accum2)
            elem0 = val1[k0]
            (elem1, accum4) = preorder_mapfold(elem0, f, accum3)
            ret[k1] = elem1
            accum2 = accum4
        return (ret, accum2)
    elif isinstance(val1, set):
        ordered_elems = sorted(list(val1))
        ret = set()
        accum2 = accum1
        for elem0 in ordered_elems:
            (elem1, accum3) = preorder_mapfold(elem0, f, accum2)
            ret.add(elem1)
            accum2 = accum3
        return (ret, accum2)
    else:
        return (val1, accum1)

def preorder_fold(val0, f, accum0):
    def g(val1, accum1):
        return (val1, f(val1, accum1))

    (val2, accum2) = preorder_mapfold(val0, g, accum0)
    return accum2

def fmap(val0, f):
    def g(val1, accum1):
        return (f(val1), accum1)

    (val2, accum2) = preorder_mapfold(val0, g, None)
    return val2

def compose(f, g):
    return lambda *a, **kw: f(g(*a, **kw))