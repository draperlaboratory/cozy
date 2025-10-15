class FieldDiff:
    def _rec_diff_str(self):
        raise NotImplementedError()

    def diff_str(self) -> str:
        return str(self._rec_diff_str())


class EqFieldDiff(FieldDiff):
    """
    For a field to be equal, all subcomponents of the body must be equal. In this case, left_body and right_body
    should not hold any further FieldDiffs within themselves. Rather left_body and right_body should be the entire
    fields for which differencing was checked (and it was determined that all subfields are equal).
    """
    def __init__(self, left_body, right_body):
        self.left_body = left_body
        self.right_body = right_body

    def _rec_diff_str(self):
        return None

    def __str__(self):
        return f"EqFieldDiff({self.left_body, self.right_body})"

    def __repr__(self):
        return self.__str__()


class NotEqLeaf(FieldDiff):
    """
    A not equal leaf is a field that cannot be further unpacked/traversed.
    """
    def __init__(self, left_leaf, right_leaf):
        self.left_leaf = left_leaf
        self.right_leaf = right_leaf

    def _rec_diff_str(self):
        return (self.left_leaf, self.right_leaf)

    def __str__(self):
        return f"NotEqLeaf({self.left_leaf, self.right_leaf})"

    def __repr__(self):
        return self.__str__()


class NotEqFieldDiff(FieldDiff):
    """
    For a field to be not equal, there must be at least one subcomponent of the body that was not equal. In this case,
    body_diff will hold further FieldDiffs within itself. Equal subfields of the bodies will be
    represented by EqFieldDiff, whereas unequal subfields will be represented by further nested NotEqFieldDiff.
    """
    def __init__(self, body_diff: list[FieldDiff] | tuple[FieldDiff, ...] | dict[str | int, FieldDiff]):
        # body_diff is a zipped data structure. For example, if body_diff is a list, it will be a list of FieldDiff
        # objects, one for each zipped element. If body_diff is a dict, it will be a dict with string keys, and values
        # of FieldDiff objects.
        self.body_diff = body_diff

    def _rec_diff_str(self):
        if isinstance(self.body_diff, list):
            return [elem.diff_str() for elem in self.body_diff]
        elif isinstance(self.body_diff, tuple):
            return tuple(elem.diff_str() for elem in self.body_diff)
        elif isinstance(self.body_diff, dict):
            ret = dict()
            for (k, v) in self.body_diff.items():
                if not isinstance(v, EqFieldDiff):
                    ret[k] = v._rec_diff_str()
            return ret

    def __str__(self):
        return f"NotEqFieldDiff({self.body_diff})"

    def __repr__(self):
        return self.__str__()
