import claripy

from .constants import *

name_ctr = 0

def sym_ptr(name=None):
    global name_ctr
    if name is None:
        name = "symbolic_ptr_{}".format(name_ctr)
        name_ctr += 1
    return claripy.BVS(name, PTR_SIZE * 8)

def sym_ptr_constraints(symbolic_ptr, concrete_addr, can_be_null=True):
    if can_be_null:
        return (symbolic_ptr == NULL_PTR) | (symbolic_ptr == concrete_addr)
    else:
        return (symbolic_ptr == concrete_addr)

# Given an integer encoded in num_bits two's complement form, returns the corresponding Python integer
def from_twos_comp(val, num_bits):
    if (val & (1 << (num_bits - 1))) != 0:
        val = val - (1 << num_bits)
    return val

# Given a Python integer, converts that integer to a two's complement form
def to_twos_comp(val, num_bits):
    if val < 0:
        val = val % (1 << num_bits)
    else:
        val = val % (1 << (num_bits - 1))
    return val