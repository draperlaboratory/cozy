Annotations
=================================

Annotations are a new feature in cozy that allows for apples-to-apples comparisons of
memory and return results in scenarios where memory addresses do not match or
the structure of return values differ. This feature was developed primarily with
the use case of comparing C and Rust programs in mind. When comparing C and Rust
programs, the compilers are free to change the location and memory layout of data structures.
Annotations enable most simple comparisons for this use case.

We will first discuss memory annotations. These types of annotations are used to give
a *path* to a specific location in memory. A path is a sequence of strings or integers,
and are used to give a name to that particular memory location. When cozy computes
a diff between two terminal states, a piece of memory from the first program is compared
with a piece of memory from the second program based on the path name.

Let's take a look at a simple example of how to use memory annotations. This snippet
is taken from the cross_language_sort.py example, which demonstrates cozy's
capability of comparing with both a difference in language (C vs Rust) and algorithm
implementation (bubble sort vs insertion sort)::

        # Set up the session before we run it
        for i in range(max_num_count):
            # Put the symbols into the program's memory
            sess.mem[arr + i * 4].int = array_numbers[i]
            # Annotate the memory for each array element. In this case the
            # memory will be annotated with the path ("input_arr", i) for
            # each element.
            # Note here that the second parameter is an angr memory view
            sess.annotate_memory(("input_arr", i), sess.mem[arr + i * 4].int)

Return annotations are the second type of memory annotations. As this name suggests,
these annotations can be used to annotate the return value of some particular function.
Here we will take an example from the int_ret_struct.py example, which makes a comparison
between a correct vs incorrect implementation of a 3D vector integer cross product::

    cozy.types.register_type('struct Vector3 { int x; int y; int z; }', proj_a.arch)
    def annotator(state, value, typ):
        # The value passed to this annotator will be a SimStructValue that was
        # extracted by angr from the return of the function
        # Here we provide a simple annotation of the return value, splitting the
        # SimStructValue into its component fields
        # Our annotation paths are given by the paths in the return
        # dictionary
        return { "x": value.x, "y": value.y, "z": value.z }
    # Call this method to run the project once
    def run_a(proj: cozy.project.Project):
        proj.add_prototype('crossProduct', 'struct Vector3 crossProduct(struct Vector3 a, struct Vector3 b)')
        sess = proj.session('crossProduct')
        results = sess.run(program_args)
        results.annotate_return(annotator)
        return results

In this case angr understands that the return value is a struct, and our annotator
will be passed a :py:class:`angr.sim_type.SimStructValue`. This value is the return
value from the crossProduct function. Our annotator function will be called
multiple times, once for each terminal state that provides a return value. The return
value from our annotator should be a nested dictionary where the keys are strings
or integers. The path through this nested dictionary is the path for this particular
return annotated value.

Note that annotations are treated as a separate comparison from registers and memory.
You can choose what type of comparisons you'd like to make by passing the appropriate
enum flag to the constructor of :py:class:`cozy.analysis.Comparison`. If you'd like
to compare only memory and return annotations and skip all other comparisons, you can
pass in this flag::

    cozy.analysis.ComparisonOptions.COMPARE_ANNOTATED_MEMORY | cozy.analysis.ComparisonOptions.COMPARE_ANNOTATED_RETURN
