import angr
from angr.storage.memory_mixins import DefaultMemory


class SimConcretizationStrategyNorepeatsRangeMin(angr.concretization_strategies.SimConcretizationStrategyNorepeatsRange):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extra_constraints = []
        self.single = angr.concretization_strategies.SimConcretizationStrategySingle()

    def _concretize(self, memory, addr, **kwargs):
        single_value = self.single._concretize(memory, addr, extra_constraints=self.extra_constraints)
        if single_value is not None:
            return single_value
        else:
            results = super()._concretize(memory, addr, extra_constraints=self.extra_constraints)
            self.extra_constraints.append(results[0] == addr)
            return results

    def _any(self, *args, **kwargs):
        # The default SimConcretizationStrategyNorepeatsRange class chooses a concrete address using the _any
        # method. By using this class, we redirect the _any call to _min instead. This ensures that the concretized
        # address is low in memory, guaranteeing sufficient space for member contents of the object that may
        # be located at the symbolic address.
        return self._min(*args, **kwargs)

class DefaultMemoryUnderconstrained(DefaultMemory):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_backer = DefaultMemory(*args, **kwargs)

    def set_default_backer(self, backer: DefaultMemory):
        self.default_backer = backer

    def copy(self, *args, **kwargs):
        o = super().copy(*args, **kwargs)
        o.default_backer = self.default_backer
        return o

    def _default_value(self, addr, size, **kwargs):
        if angr.sim_options.UNDER_CONSTRAINED_SYMEXEC in self.state.options and type(addr) is int:
            self.default_backer.state = self.state
            return self.default_backer.load(addr, size)
        return super()._default_value(addr, size, **kwargs)

underconstrained_preset = angr.SimState._presets['default'].copy()
underconstrained_preset.add_default_plugin("sym_memory", DefaultMemoryUnderconstrained)
angr.SimState.register_preset("underconstrained", underconstrained_preset)