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