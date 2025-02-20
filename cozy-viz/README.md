# cozy-viz

This is a visualization tool for symbolic execution traces generated by cozy.
You can use it to explore the tree of possible behaviors of a binary, before
and after the application of a patch.

## Usage

### Running

To use cozy-viz locally, you'll need to serve the contents of this directory.
`python -m http.server` will generally do the trick. If you'd like a fancier
development-oriented server, and you have nix installed and flakes enabled, you
can `nix run` to fire up a configured `browser-sync`. If you've installed cozy
with `pip`, you should also be able to launch cozy-viz using the functions in
cozy's `server.py`—check [the
documentation](https://draperlaboratory.github.io/cozy/launchingavisualization.html)
for that. A script generated using [cozy's template generation
wizard](..#template-wizard) can also be configured to use this mechanism to
launch cozy's visualization server.

### Loading Traces

Once you have cozy-viz running in your browser, you need a JSON export of
a comparative symbolic execution. Example traces are available as artifacts
from Cozy's CI builds,
[here](https://github.com/draperlaboratory/cozy/actions/). Drag and drop the
trace into the browser window where you've opened cozy-viz. After a moment, you
should see two trees, representing the possible execution paths in the two
traces.

### Comparing Branches

To compare two execution paths, you can start by mousing over nodes in the
prepatch tree. A tooltip will let you see information associated with each
node: blocks of assembly, logical constraints on arguments, stdout and stderr
contents, any error messages associated with failed states (failed states are
highlighted in a light red color), and potentially some other properties.

Once you've found an interesting execution path in the prepatch tree, click on
the terminal node of the path. The right tree will then highlight the branches
that could occur, consistent with the constraints on input required to produce
the first branch you selected. You can explore these "compatible" branches
using the tooltip, and select one by clicking its terminal node.

#### Comparison Tools

When you select a compatible branch, a number of comparison tools become
available. You should see one or more buttons at the bottom of the screen light
up to indicate their availability. Each of these buttons provides a comparison
tool that you can use to compare the two selected branches. The set of
available comparison tools will depend on exactly what information was packed
into the traces during symbolic execution.[^1]

[^1]: Check out the parameters documented
    [here](https://draperlaboratory.github.io/cozy/autoapi/cozy/execution_graph/index.html#cozy.execution_graph.dump_comparison)
    to get a sense of the options.

The available tools are:

1. Assembly: this performs a git-style diff on the stream of assembly
   instructions executed along the two branches. If DWARF debug data is
   available and enabled in cozy, a mouse hover over a piece of assembly will
   show the corresponding line number in the original source.
2. Memory: this provides a comparison of any possible differences in memory
   contents for the two branches, at the end of execution. These differences
   can be presented symbolically, or in the form of concrete examples of
   possible memory contents.
3. Registers: this is analogous to the Memory panel, but for registers. Both
   concrete and symbolic comparisons are available.
4. Concretions: this tool compares the inputs that produce each of the selected
   pair of compatible branches. If there are inputs that produce one of the
   branches but not the other, you'll see that here, along with some examples.
   You'll also be able to find examples of inputs that produce both of the two
   branches.
5. Actions: this performs a git-style diff on the "actions" performed along
   each of the branches. Actions correspond to `SimActions` recorded in Angr's
   `SimStateHistory`[^2] along the path. Essentially, they amount to a listing
   of interesting behaviors, including memory and register reads and writes,
   along the branches.
6. Side Effects: this performs a git-style diff on configurable side-effects
   encountered along each of the branches, like "virtual print" directives that
   might print out a bit of program state. Documentation for producing
   side-effects during symbolic execution can be found
   [here](https://draperlaboratory.github.io/cozy/sideeffects.html).

[^2]: https://docs.angr.io/en/latest/api.html#angr.state_plugins.history.SimStateHistory.actions

To compare a different set of branches, click a new terminal node in the left
pane. This will highlight a new set of compatible branches on the right, and
you can select one of those as above.

### Refining The View

The initial view presented by dragging in a trace is fully expanded: each basic
block along each execution path is a node, all basic blocks are displayed, and
all nodes with special features are highlighted. This can be a lot of
information to deal with. To refine the view, you can use some of the menu
options at the top of the cozy-viz window. The available menu options are:

1. File: this contains options for saving the trace you're currently viewing as
   a file. This can be useful if you've summoned the visualizer from a script
   with a preloaded trace, and it turns out you'd like to save that trace. It
   also contains an option for creating a *report* (see below for more
   information about reports).
2. View: this contains options for toggling the visibility of the different
   kinds of special nodes: errors, [failed
   post-conditions](https://draperlaboratory.github.io/cozy/autoapi/cozy/directive/index.html#cozy.directive.Postcondition),
   [failed
   asserts](https://draperlaboratory.github.io/cozy/autoapi/cozy/directive/index.html#cozy.directive.Assert),
   nodes containing syscalls, and nodes containing simulated procedure calls.
   The view menu also includes options for changing the "granularity" of the
   view, either by merging sequences of nodes in which the constraints on input
   don't change, or merging all sequences of nodes where no forking occurs.
3. Prune: this lets you toggle different "prunings", which remove branchings
   that aren't interestingly different from any of their compatible partners.
   Options include pruning branches that don't differ from their partners in
   memory contents, register contents, input constraints, stdout, or branches
   whose stdout contents satisfy some regex also satisfied by all their
   partners.
4. Layout: this lets you change the way the symbolic execution is laid out,
   displaying it as a CFG using one of several graph-layout algorithms. Note
   that while the symbolic execution is laid out as a CFG, it won't be possible
   to select or compare pairs of branches in the ordinary way, since the CFG
   obscures which sequences of nodes are branches in the symbolic execution.
5. Search: this lets you highlight sets of nodes whose stdout matches a certain
   regex.

### Report Generation

The "Report" option under the file menu will create a *report* in a new window.
For each branch in the left pane which is visible (not pruned) when the report
is created, the report will contain a text field where notes about that branch
and its partners can be recorded. Branches can be checked off as "reviewed" by
clicking the checkboxes within the report. Reviewed branches will show an × in
their final node, and can be hidden from view using one of the pruning options
under the "prune" menu. Once a report is completed, it can be printed as a PDF.
