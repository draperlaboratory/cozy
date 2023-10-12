import collections.abc

def remove_range_list(input_set: set[int], range_list: collections.abc.Iterable[range]):
    elems_to_remove = set()
    for elem in input_set:
        for rng in range_list:
            if elem in rng:
                elems_to_remove.add(elem)
                break
    input_set.difference_update(elems_to_remove)

def intersect_range(range_a: range, range_b: range):
    return range(max(range_a[0], range_b[0]), min(range_a[-1], range_b[-1]) + 1)