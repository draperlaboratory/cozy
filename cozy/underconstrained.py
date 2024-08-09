import angr
from angr.storage.memory_mixins import DefaultMemory

import cozy.log
from cozy import claripy_ext


class SimConcretizationStrategyUnderconstrained(angr.concretization_strategies.SimConcretizationStrategyNorepeatsRange):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extra_constraints = []
        self.single = angr.concretization_strategies.SimConcretizationStrategySingle()
        self.multiple = angr.concretization_strategies.SimConcretizationStrategyUnlimitedRange(16)
        self.extra_constraints_symbols = set()

    def constrain_addr(self, memory, addr):
        if addr not in self.extra_constraints_symbols:
            results = super()._concretize(memory, addr, extra_constraints=self.extra_constraints)
            self.extra_constraints.append(addr == results[0])
            self.extra_constraints_symbols.add(addr)

    def _concretize(self, memory, addr, **kwargs):
        single_value = self.single._concretize(memory, addr, extra_constraints=self.extra_constraints)
        if single_value is not None:
            return single_value
        else:
            children = claripy_ext.sym_variables(addr)

            if len(children) == 1:
                # If there is only one child, constrain that child to be some concrete address
                # This is the most common case for accessing a field inside a struct
                self.constrain_addr(memory, list(children)[0])
                # We have now constrained the symbolic variable to be a concrete variable
                # If we evaluate addr now, the compound expression should now evaluate to a single value
                return self.single._concretize(memory, addr, extra_constraints=self.extra_constraints)
            else:
                # If there are multiple children, we are likely accessing an array. In this case we should
                # genuinely concretize to multiple values since the index into the array can be multiple values.
                # Now let's use a heuristic to try to figure out what is the address of the array start
                # and what is the variable that corresponds to the index. For anything but uint8_t/char arrays,
                # the array variable will be the child of an add operation, and the index will be multiplied or bit
                # shifted. For example with an int array, the addr expression will be ARRAY + SignExt(32, INDEX << 2)
                array_candidates = set(children)
                for expr in claripy_ext.sub_asts(addr):
                    if expr.op != '__add__' and expr.op != '__sub__':
                        for child in expr.args:
                            if child in array_candidates:
                                array_candidates.remove(child)
                if len(array_candidates) == 1:
                    self.constrain_addr(memory, list(array_candidates)[0])
                else:
                    cozy.log.warning("Unable to find array base when concretizing symbolic address")
                return self.multiple._concretize(memory, addr, extra_constraints=self.extra_constraints)

    def _any(self, *args, **kwargs):
        # The default SimConcretizationStrategyNorepeatsRange class chooses a concrete address using the _any
        # method. By using this class, we redirect the _any call to _min instead. This ensures that the concretized
        # address is low in memory, guaranteeing sufficient space for member contents of the object that may
        # be located at the symbolic address.
        return self._min(*args, **kwargs)

class Box:
    def __init__(self, value):
        self.value = value

class DefaultMemoryUnderconstrained(DefaultMemory):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make a box so that if we change the backer in any copies, all copies get the update
        self.default_backer = Box(DefaultMemory(*args, **kwargs))

    def get_default_backer(self):
        return self.default_backer.value

    def set_default_backer(self, backer: DefaultMemory):
        self.default_backer.value = backer

    def copy(self, *args, **kwargs):
        o = super().copy(*args, **kwargs)
        o.default_backer = self.default_backer
        return o

    def _default_value(self, addr, size, **kwargs):
        if angr.sim_options.UNDER_CONSTRAINED_SYMEXEC in self.state.options and type(addr) is int:
            self.default_backer.value.state = self.state
            return self.default_backer.value.load(addr, size)
        return super()._default_value(addr, size, **kwargs)

underconstrained_preset = angr.SimState._presets['default'].copy()
underconstrained_preset.add_default_plugin("sym_memory", DefaultMemoryUnderconstrained)
angr.SimState.register_preset("underconstrained", underconstrained_preset)