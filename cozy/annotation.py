import claripy

from cozy.field_diff import FieldDiff, EqFieldDiff
from cozy.nested_dict import NestedDict

class AnnotationDiff:
    def __init__(self, diff: FieldDiff, left: NestedDict[claripy.ast.Bits], right: NestedDict[claripy.ast.Bits]):
        self.diff = diff
        self.left = left
        self.right = right

    @property
    def is_equal(self) -> bool:
        return isinstance(self.diff, EqFieldDiff)