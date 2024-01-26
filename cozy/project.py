import os
import pickle
from collections.abc import Callable

import angr
from cle import Backend

from cozy.session import Session


class Project:
    """
    Represents a project for a single executable

    :ivar angr.Project angr_proj: The angr project created for this cozy project.
    :ivar dict[str | int, str] fun_prototypes: Maps function names or function addresses to their type signatures.
    """

    def __init__(self, binary_path: str, fun_prototypes: dict[str | int, str] | None=None, load_debug_info: bool = False):
        """
        Constructor for a project.

        :param str binary_path: The path to the binary to analyze.
        :param dict[str | int, str] | None fun_prototypes: Initial dictionary that maps function names or addresses to their type signatures. If None is passed, fun_prototypes is initialized to the empty dictionary.
        """
        self.angr_proj = angr.Project(binary_path, load_debug_info=load_debug_info)
        if fun_prototypes is None:
            self.fun_prototypes = {}
        else:
            self.fun_prototypes = fun_prototypes
        self.cached_cfg = None

    def object_ranges(self, obj_filter: Callable[[Backend], bool] | None=None) -> list[range]:
        """
        Returns the ranges of the objects stored in the executable (for example: ELF objects). If obj_filter is specified, only objects that pass the filter make it into the return list.

        :param Callable[[Backend], bool] | None obj_filter: Used to filter certain objects from the output list.
        :return: A list of memory ranges.
        :rtype: list[range]
        """
        if obj_filter is None:
            obj_filter = lambda x: True
        return [range(obj.min_addr, obj.max_addr + 1) for obj in self.angr_proj.loader.all_objects if obj_filter(obj)]

    def find_symbol_addr(self, sym_name: str) -> int:
        """
        Finds the rebased addressed of a symbol. Functions are the most common symbol type.

        :param str sym_name: The symbol to lookup.
        :return: The rebased symbol address
        :rtype: int
        """
        return self.angr_proj.loader.find_symbol(sym_name).rebased_addr

    # fun can be either the address of a function or a function name
    def add_prototype(self, fun: str | int, fun_prototype: str) -> None:
        """
        Adds a function prototype to this project.

        :param str | int fun: The function's name or address.
        :param str fun_prototype: The function's type signature.
        :return: None
        :rtype: None
        """
        self.fun_prototypes[fun] = fun_prototype

    def session(self, start_fun: str | int | None=None) -> Session:
        """
        Returns a new session derived from this project.

        :param str | int | None start_fun: The name or address of the function which this session will start with. If None is specified, then the program will start at the entry point (main function).
        :return: The fresh session.
        :rtype: Session
        """
        return Session(self, start_fun=start_fun)

    @property
    def cfg(self):
        if self.cached_cfg is None:
            cfg_filename = self.angr_proj.filename + ".cfg.pickle"
            if os.path.exists(cfg_filename):
                with open(cfg_filename, 'rb') as f:
                    self.cached_cfg = pickle.load(f)
            else:
                print("Computing CFG... this may take some time")
                self.cached_cfg = self.angr_proj.analyses.CFGFast()
                print("Done computing CFG!")
                with open(cfg_filename, 'wb') as f:
                    pickle.dump(self.cached_cfg, f)
        return self.cached_cfg

    @property
    def arch(self):
        return self.angr_proj.arch