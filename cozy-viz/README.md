# angr-viz

This is a visualization tool for symbolic execution traces generated by hungr.
You can use it to explore the tree of possible behaviors of a binary, before
and after the application of a patch.

## Usage


https://github.com/draperlaboratory/VIBES-internal/assets/6383381/05e2b78b-3839-4f12-ac27-a62cae9d9349


### Running

To use angr-viz locally, you'll need to serve the directory contents. `python
-m http.server` will generally do the trick. If you'd like a fancier
development-oriented server, and you have nix installed and flakes enabled, you
can `nix run` to fire up a configured `browser-sync`.

### Loading Traces

Once you have the application running in your browser, you need JSON exports of
two symbolic execution traces. Some example pairs of traces are available under
example-traces. Drag and drop one export into the left "prepatch" pane, and one
into the right "postpatch" pane. After a moment, you should see two trees,
representing the possible execution paths in the two traces.

### Comparing Branches

To compare two execution paths, you can start by mousing over nodes in the
prepatch tree. A tooltip will let you see information associated with each
node: blocks of assembly, logical constraints on arguments, stdout and stderr
contents, and any error messages associated with failed states (failed states
are highlighted in a light red color).

Once you've found an interesting execution path in the prepatch tree, click on
the terminal node of the path. The right tree will then highlight the branches
that could occur, compatible with the constraints in input that produce the
first branch you selected. You can explore these compatible branches using the
tooltip, and select one by clicking its terminal node.

When you select a compatible branch, a number of comparison tools become
enabled. You should see one or more buttons at the bottom of the screen light
up to indicate their availability. Clicking these buttons will display things
like a diff of the sequence of assembly instructions associated with the left
and right paths, a diff of the constraints on memory and registers contents,
and a set of "concretions" - concrete values that, when given as input to the
prepatched function, produce the behavior on the left, and when given as input
to the postpatched function, produce the behavior on the right.

To compare a different set of branches, click a new terminal node in the left
pane. This will highlight a new set of compatible branches on the right, and
you can select one of those as above.

## Data Format

Symbolic execution traces are graphs formatted using
[networkx](https://networkx.org) for rendering via
[cytoscape.js](https://js.cytoscape.org)

The basic format is:

``` 
{ 
  "data" : [],
  "directed" : true,
  "multigraph" : false,
  "elements": {
    "nodes": [
      {
        "id":"NODE_ID"
        "value": NODE_ID
        "name": "NODE_ID"
        "data": {
          "stdout": STDOUT 
          "stderr": STDERR,
          "contents": ASSEMBLY,
          "constraints": [
            CONSTRAINT, 
            …
          ],
          "compatibilities": {
            COMPATIBLE_NODE_ID : {
              "memdiff": {
                ADDRESS: CONSTRAINT
              }
              "regdiff": {
                REGISTER: CONSTRAINT
              }
            }
            …
          },
          "conc_args": [ CONCRETION, … ]
        }
      }
      …
    ]
    "edges" : [
      {
        "data": {
          "source": SOURCE_ID,
          "target": TARGET_ID 
        }
      }
      …
    ]
  }
} 
```

angr-viz consolidates non-branching sequences of nodes, so there are likely
more nodes listed in the JSON that will actually appear in the visualization.