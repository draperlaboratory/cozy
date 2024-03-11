import Colors from "../data/colors.js"

export const settings = {
  showingSimprocs: true,
  showingSyscalls: true,
  showingErrors: true,
  showingAsserts: true,
}

//Cytoscape doesn't have specificity - last matching selector wins.
//
//There's a bit more logic here depending on that rule than would be ideal, but
//it seems like it's best for performance to bake everything into the
//stylesheet rather than trying to change the styling rules on the fly
export const style = [
  { 
    selector: "node",
    style: {
      'shape': 'round-rectangle',
      'background-color': Colors.defaultNode,
      'border-color': Colors.defaultBorder,
    },
  },
  { 
    selector: "[[outdegree = 0]][!error]",
    style: { 'border-width': '5px' },
  },
  {
    selector: 'edge',
    style: {
      'width': 3,
      'line-color': Colors.defaultEdge,
      'target-arrow-color': Colors.defaultEdge,
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier'
    }
  },
  {
    selector: 'edge.pathHighlight',
    style: {
      'width': 3,
      'line-color': Colors.focusedEdge,
      'target-arrow-color': Colors.focusedEdge,
      'target-arrow-shape': 'triangle',
      'z-compound-depth' : 'top',
      'curve-style': 'bezier'
    }
  },
  {
    selector: 'node.pathHighlight',
    style: { 'background-color': Colors.focusedNode }
  },
  {
    selector: 'node[?has_syscall]',
    style: { 'background-color': () => settings.showingSyscalls
      ? Colors.syscallNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node.pathHighlight[?has_syscall]',
    style: { 'background-color': () => settings.showingSyscalls
      ? Colors.syscallNode
      : Colors.focusedNode
    }
  },
  {
    selector: 'node[simprocs.length > 0]',
    style: { 'background-color': () => settings.showingSimprocs
      ? Colors.simprocNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node.pathHighlight[simprocs.length > 0]',
    style: { 'background-color': () => settings.showingSimprocs
      ? Colors.simprocNode
      : Colors.focusedNode
    }
  },
  { selector: "node.temporaryFocus",
    style: { 
      'underlay-color': '#708090',
      'underlay-opacity': 0.5,
    }
  },
  {
    selector: 'node[?error], node[?assertion_info]',
    style: { 'background-color': () => settings.showingErrors
      ? Colors.errorNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node[?assertion_info]',
    style: { 'background-color': () => settings.showingAsserts
      ? Colors.assertNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node.pathHighlight[?assertion_info]',
    style: {
      'border-width':'0px',
      'background-color': () => settings.showingAsserts
      ? Colors.focusedAssertNode
      : Colors.focusedNode
    }
  },
  {
    selector: 'node.pathHighlight[?error]',
    style: {
      'border-width':'0px',
      'background-color': () => settings.showingErrors
      ? Colors.focusedErrorNode
      : Colors.focusedNode
    }
  },
  {
    selector: 'node.availablePath',
    style: {
      'border-width':'5px',
      'border-color': Colors.focusedNode
    }
  },
]
