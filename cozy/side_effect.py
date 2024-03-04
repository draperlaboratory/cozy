from angr import SimState
from angr.state_plugins import SimStateHistory


class PerformedSideEffect:
    """
    This class encapsulates the idea of a side effect whose body may consist of mixed symbolic and concrete values.
    """
    def __init__(self, state_history: SimStateHistory, body, concrete_mapper=None):
        """
        :param body: The body must be a mixture of string-keyed Python dictionaries, Python lists, Python tuples, and\
        claripy concrete and symbolic values.
        """
        self.state_history = state_history
        self.body = body
        self.concrete_mapper = concrete_mapper

class ConcretePerformedSideEffect:
    """
    This class encapsulates the idea of a side effect whose body previously consisted of mixed symbolic and concrete
    values, but now consists of only concrete values (ie, BVV and FPV). At the point of the construction, this concrete
    value has not yet been passed through the user provided concrete_mapper, whose job is to take the concrete value
    and transform the BVV values into ordinary Python values. The purpose of concrete_mapper for instance could be
    to transform a two's complement BVV that is negative into a negative Python integer. This will make the display
    more readable to the user. Hence, the concrete_mapper can be viewed as a post-processing function.
    """
    def __init__(self, base_effect: PerformedSideEffect, state_history: SimStateHistory, body, concrete_mapper=None):
        """
        :param body: The body must be a mixture of string-keyed Python dictionaries, Python lists, Python tuples, and\
        claripy concrete values.
        """
        self.base_effect = base_effect
        self.state_history = state_history
        self.body = body
        self.concrete_mapper = concrete_mapper

    @property
    def mapped_body(self):
        return self.concrete_mapper(self.body) if self.concrete_mapper is not None else self.body

def perform(state: SimState, channel: str, body, concrete_mapper=None):
    if channel in state.globals['side_effects']:
        accum_side_effects = state.globals['side_effects'][channel].copy()
    else:
        accum_side_effects = []
    accum_side_effects.append(PerformedSideEffect(state.history, body, concrete_mapper=concrete_mapper))
    state.globals['side_effects'][channel] = accum_side_effects

def get_effects(state: SimState) -> dict[str, list[PerformedSideEffect]]:
    return state.globals['side_effects']

def get_channel(state: SimState, channel: str) -> list[PerformedSideEffect]:
    return state.globals['side_effects'].get(channel, [])