import angr
from angr.sim_type import SimType
from archinfo import Arch

def register_type(type_definition: str, arch: Arch) -> SimType:
    """
    Parses a C-style type definition given in the input string, assuming the given architecture. Registers this type\
    with angr.

    :param str type_definition: The type definition, given in C-style format.
    :param Arch arch: The architecture this type should be used with.
    :return: The parsed typed.
    :rtype: SimType
    """
    t = angr.types.parse_type(type_definition).with_arch(arch)
    angr.types.register_types(t)
    return t

def register_types(type_definition: str) -> SimType:
    """
    Parses a series of type definition given in the input string. Registers this type with angr.

    :param str type_definition: The type definition, given in C-style format.
    :param Arch arch: The architecture this type should be used with.
    :return: The parsed typed.
    :rtype: SimType
    """
    t = angr.types.parse_types(type_definition)
    angr.types.register_types(t)
    return t
