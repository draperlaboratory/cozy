from cozy.nested_dict import NestedDict


class FieldDiff:
    def _rec_diff_str(self):
        raise NotImplementedError()

    def diff_str(self) -> str:
        return str(self._rec_diff_str())

    def _rec_compute_neq(self, left: bool):
        raise NotImplementedError()

    def _compute_neq(self, left: bool):
        if isinstance(self, EqFieldDiff):
            return NestedDict.empty()
        elif isinstance(self, NotEqLeaf):
            return NestedDict({"value": self._rec_compute_neq(left)})
        else:
            return NestedDict(self._rec_compute_neq(left))

    def left_neq(self) -> NestedDict:
        return self._compute_neq(True)

    def right_neq(self) -> NestedDict:
        return self._compute_neq(False)

    @property
    def is_equal(self):
        raise NotImplementedError()

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

    def _rec_compute_neq(self, left: bool):
        return dict()

    @property
    def is_equal(self):
        return True

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

    def _rec_compute_neq(self, left: bool):
        if left:
            return self.left_leaf
        else:
            return self.right_leaf

    @property
    def is_equal(self):
        return False

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

    def _rec_compute_neq(self, left: bool):
        if isinstance(self.body_diff, list) or isinstance(self.body_diff, tuple):
            ret = dict()
            for (i, elem) in enumerate(self.body_diff):
                if not isinstance(elem, EqFieldDiff):
                    ret[i] = elem._rec_compute_neq(left)
            return ret
        elif isinstance(self.body_diff, dict):
            ret = dict()
            for (k, v) in self.body_diff.items():
                if not isinstance(v, EqFieldDiff):
                    ret[k] = v._rec_compute_neq(left)
            return ret

    @property
    def is_equal(self):
        return False