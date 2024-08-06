import angr

class SimConcretizationStrategyNorepeatsRangeMin(angr.concretization_strategies.SimConcretizationStrategyNorepeatsRange):
    def _any(self, *args, **kwargs):
        # The default SimConcretizationStrategyNorepeatsRange class chooses a concrete address using the _any
        # method. By using this class, we redirect the _any call to _min instead. This ensures that the concretized
        # address is low in memory, guaranteeing sufficient space for member contents of the object that may
        # be located at the symbolic address.
        return self._min(*args, **kwargs)