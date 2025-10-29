import claripy

from cozy.field_diff import FieldDiff, EqFieldDiff
from cozy.nested_dict import NestedDict

class AnnotationDiff:
    """
    This class contains three pieces of information. The first is diff, which contains the symbolic diff of\
    some annotations. The second and third pieces are left and right, which are the\
    :py:class:`~cozy.nested_dict.NestedDict` objects that were under comparison. These objects are bundled here\
    since later on in the program they will be concretized to show to the user.
    """
    def __init__(self, diff: FieldDiff, left: NestedDict[claripy.ast.Bits], right: NestedDict[claripy.ast.Bits]):
        self.diff = diff
        self.left = left
        self.right = right

    @property
    def is_equal(self) -> bool:
        return isinstance(self.diff, EqFieldDiff)