import collections.abc

def remove_range_list(input_set: set[int], range_list: collections.abc.Iterable[range]) -> None:
    """
    Removes elements from the input_set that lie in any range in the range_list. Essentially mutates input_set to contain input_set - range_list.

    :param set[int] input_set: The input set which should be mutated.
    :param collections.abc.Iterable[range] range_list: The list of ranges to be removed from input_set.
    :return: None
    :rtype: None
    """
    elems_to_remove = set()
    for elem in input_set:
        for rng in range_list:
            if elem in rng:
                elems_to_remove.add(elem)
                break
    input_set.difference_update(elems_to_remove)

def intersect_range(range_a: range, range_b: range) -> range:
    """
    Computes the intersection of two ranges.

    :param range range_a: The first range
    :param range range_b: The second range
    :return: The intersection of range_a and range_b
    :rtype: range
    """
    return range(max(range_a[0], range_b[0]), min(range_a[-1], range_b[-1]) + 1)

def subtract_range(range_a: range, range_b: range) -> list[range]:
    if range_a.start == range_a.stop:
        return []
    elif range_b.start == range_b.stop:
        return [range_a]
    elif range_a[-1] < range_b[0] or range_b[-1] < range_a[0]:
        return [range_a]
    elif range_b[0] <= range_a[0] and range_a[-1] <= range_b[-1]:
        return []
    elif range_a[0] < range_b[0] and range_b[-1] < range_a[-1]:
        return [range(range_a[0], range_b[0]), range(range_b[-1] + 1, range_a[-1] + 1)]
    elif range_a[0] < range_b[0]:
        return [range(range_a[0], range_b[0])]
    else:
        return [range(range_b[-1] + 1, range_a[-1] + 1)]

def subtract_range_lists(ranges_a: list[range], ranges_b: list[range]) -> list[range]:
    ret = ranges_a
    for rb in ranges_b:
        ranges_a_prime = []
        for ra in ret:
            ranges_a_prime.extend(subtract_range(ra, rb))
        ret = ranges_a_prime
    return ret
