from angr import SimState
from angr.state_plugins import SimStateHistory


class PerformedSideEffect:
    """
    This class encapsulates the idea of a side effect whose body may consist of mixed symbolic and concrete values.
    """
    def __init__(self, state_history: SimStateHistory, body, concrete_mapper=None, label=None):
        """
        :param body: The body must be a mixture of string-keyed Python dictionaries, Python lists, Python tuples, and\
        claripy concrete and symbolic values.
        """
        self.state_history = state_history
        self.body = body
        self.concrete_mapper = concrete_mapper
        self.label = label

class ConcretePerformedSideEffect:
    """
    This class encapsulates the idea of a side effect whose body previously consisted of mixed symbolic and concrete
    values, but now consists of only concrete values (ie, BVV and FPV). At the point of the construction, this concrete
    value has not yet been passed through the user provided concrete_mapper, whose job is to take the concrete value
    and transform the BVV values into ordinary Python values. The purpose of concrete_mapper for instance could be
    to transform a two's complement BVV that is negative into a negative Python integer. This will make the display
    more readable to the user. Hence, the concrete_mapper can be viewed as a post-processing function.
    """
    def __init__(self, base_effect: PerformedSideEffect, state_history: SimStateHistory, body, concrete_mapper=None, label=None):
        """
        :param body: The body must be a mixture of string-keyed Python dictionaries, Python lists, Python tuples, and\
        claripy concrete values.
        """
        self.base_effect = base_effect
        self.state_history = state_history
        self.body = body
        self.concrete_mapper = concrete_mapper
        self.label = label

    @property
    def mapped_body(self):
        return self.concrete_mapper(self.body) if self.concrete_mapper is not None else self.body

def perform(state: SimState, channel: str, body, concrete_mapper=None, label=None):
    if channel in state.globals['side_effects']:
        accum_side_effects = state.globals['side_effects'][channel].copy()
    else:
        accum_side_effects = []
    accum_side_effects.append(PerformedSideEffect(state.history, body, concrete_mapper=concrete_mapper, label=label))
    state.globals['side_effects'][channel] = accum_side_effects

def get_effects(state: SimState) -> dict[str, list[PerformedSideEffect]]:
    return state.globals['side_effects']

def get_channel(state: SimState, channel: str) -> list[PerformedSideEffect]:
    return state.globals['side_effects'].get(channel, [])


# Memoized recursive implementation of a Levenshtein alignment algorithm,
# except that we do not do 'replacements'
# See https://en.wikipedia.org/wiki/Levenshtein_distance#Recursive for an overview of this algorithm
def levenshtein_alignment(lst_a, lst_b, key=None):
    # Create the memoization table
    table = [[None for j in range(len(lst_b) + 1)] for i in range(len(lst_a) + 1)]

    def rec_ldistance(idx_a, idx_b):
        nonlocal table
        if table[idx_a][idx_b] is not None:
            # Check if we've already memoized
            return table[idx_a][idx_b]
        else:
            len_a = len(lst_a) - idx_a
            len_b = len(lst_b) - idx_b
            if len_a == 0:
                score = len_b
                aligned = list(zip([None] * len_b, lst_b[idx_b:]))
                ret = (score, aligned)
            elif len_b == 0:
                score = len_a
                aligned = list(zip(lst_a[idx_a:], [None] * len_b))
                ret = (score, aligned)
            elif ((key is None and lst_a[idx_a] == lst_b[idx_b]) or
                  (key is not None and key(lst_a[idx_a]) == key(lst_b[idx_b]))):
                (score, rec) = rec_ldistance(idx_a + 1, idx_b + 1)
                ret = (score, [(lst_a[idx_a], lst_b[idx_b])] + rec)
            else:
                (rec_score_1, rec_1) = rec_ldistance(idx_a, idx_b + 1)
                score_1 = 1 + rec_score_1
                (rec_score_2, rec_2) = rec_ldistance(idx_a + 1, idx_b)
                score_2 = 1 + rec_score_2
                (rec_score_3, rec_3) = rec_ldistance(idx_a + 1, idx_b + 1)
                score_3 = 1 + rec_score_3

                def argmin(a):
                    return min(range(len(a)), key=lambda x: a[x])

                min_choice = argmin([score_1, score_2, score_3])
                if min_choice == 0:
                    score = score_1
                    aligned = [(None, lst_b[idx_b])] + rec_1
                    ret = (score, aligned)
                elif min_choice == 1:
                    score = score_2
                    aligned = [(lst_a[idx_a], None)] + rec_2
                    ret = (score, aligned)
                else:
                    score = score_3
                    aligned = [(lst_a[idx_a], None), (None, lst_b[idx_b])] + rec_3
                    ret = (score, aligned)
            # Save into the memoization table
            table[idx_a][idx_b] = ret
            return ret

    (score, alignment) = rec_ldistance(0, 0)
    return alignment

def test_levenshtein_alignment():
    alignment = levenshtein_alignment(['hello', 'foo', 'qux', 'bar', 'baz', 'world'], ['hello', 'bar', 'gotcha', 'world'])
    assert(alignment[0] == ('hello', 'hello'))
    assert(alignment[1] == ('foo', None))
    assert(alignment[2] == ('qux', None))
    assert(alignment[3] == ('bar', 'bar'))
    assert(alignment[4] == ('baz', None))
    assert(alignment[5] == (None, 'gotcha'))
    assert(alignment[6] == ('world', 'world'))

    alignment = levenshtein_alignment(['hello', 'hello', 'hello', 'world'], ['foo', 'foo', 'foo', 'world'])
    assert(len(alignment) == 7)