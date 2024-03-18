import os
import pickle
from collections.abc import Callable

import angr
from angr import SimProcedure
from cle import Backend

from cozy.session import Session


class Project:
    """
    Represents a project for a single executable

    :ivar angr.Project angr_proj: The angr project created for this cozy project.
    :ivar dict[str | int, str] fun_prototypes: Maps function names or function addresses to their type signatures.
    """

    def __init__(self, binary_path: str, fun_prototypes: dict[str | int, str] | None=None, load_debug_info: bool = False, **kwargs):
        """
        Constructor for a project.

        :param str binary_path: The path to the binary to analyze.
        :param dict[str | int, str] | None fun_prototypes: Initial dictionary that maps function names or addresses to their type signatures. If None is passed, fun_prototypes is initialized to the empty dictionary.
        :param kwargs: Extra arguments to pass to angr.Project
        """
        self.angr_proj = angr.Project(binary_path, load_debug_info=load_debug_info, **kwargs)
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
        sym = self.angr_proj.loader.find_symbol(sym_name)
        if sym is None:
            raise RuntimeError("Unable to find symbol named {}. Try looking through the symbol table with readelf or similar tool to make sure the symbol actually exists.".format(sym_name))
        else:
            return sym.rebased_addr

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
        """
        Returns the control flow graph for this project. This property will cache the cfg in a pickle file
        to speed up future runs. This means if you change the underlying program you will need to delete the
        .cfg.pickle file located in the same directory as your executable.
        """
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
        """
        Returns the underlying angr project architecture
        """
        return self.angr_proj.arch

    def hook_symbol(self, symbol_name: str, simproc_class: type[SimProcedure], kwargs=None, replace: bool | None=None) -> int:
        """
        Hooks a symbol in the angr project. If the symbol is one from libc, this method will also replace
        what is stored in :py:attr:`angr.SIM_PROCEDURES["libc"][symbol_name]`.

        :param str symbol_name: The name of the symbol to hook.
        :param type[SimProcedure] simproc_class: The class to use to hook the symbol. Note that this is not an instance\
        of SimProcedure, but is instead a reference to the class itself.
        :param kwargs: These are the keyword arguments that will be passed to the procedure's `run` method eventually.
        :param bool | None replace: Control the behavior on finding that the address is already hooked. If true,\
        silently replace the hook. If false, warn and do not replace the hook. If none (default), warn and replace the\
        hook.
        :rtype: int
        :return: The address of the new symbol.
        """
        if symbol_name in angr.SIM_PROCEDURES["libc"]:
            angr.SIM_PROCEDURES["libc"][symbol_name] = simproc_class
        return self.angr_proj.hook_symbol(symbol_name, simproc_class(project=self.angr_proj), kwargs=kwargs, replace=replace)

    def hook_syscall(self, syscall_name: str, simproc_class: type[SimProcedure]):
        """
        Hooks a syscall in the angr project.

        :param str syscall_name: The name of the syscall to hook.
        :param type[SimProcedure] simproc_class: The class to use to hook the symbol. Note that this is not an instance\
        of SimProcedure, but is instead a reference to the class itself.
        """
        return self.angr_proj.simos.syscall_library.add(syscall_name, simproc_class)