import Colors from "../data/colors.js"

export const settings = {
  showingSimprocs: true,
  showingSyscalls: true,
  showingErrors: true,
  showingAsserts: true,
  showingPostconditions: true,
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
    selector: "[[outdegree = 0]], node[?terminal]",
    style: { 'border-width': '5px' },
  },
  { 
    selector: "node[?initial]",
    style: { 'border-width': '5px' },
  },
  {
    selector: 'edge',
    style: {
      'width': 3,
      'line-color': Colors.defaultEdge,
      'target-arrow-color': Colors.defaultEdge,
      'target-arrow-shape': 'triangle',
      'arrow-scale': 1.5,
      'source-distance-from-node':'5px',
      'target-distance-from-node':'5px',
      'curve-style': 'bezier'
    }
  },
  {
    selector: 'edge.pathHighlight, edge[traversals > 0]',
    style: {
      'width': 3,
      'line-color': Colors.focusedEdge,
      'target-arrow-color': Colors.focusedEdge,
      'z-compound-depth' : 'top',
    }
  },
  {
    selector: 'node.pathHighlight, node[?traversed]',
    style: { 
      'background-color': Colors.focusedNode,
      'z-compound-depth' : 'top',
    }
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
    selector: 'node[?postcondition_info]',
    style: { 'background-color': () => settings.showingPostconditions
      ? Colors.postconditionNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node.pathHighlight[?postcondition_info]',
    style: {
      'border-width':'0px',
      'background-color': () => settings.showingPostconditions
      ? Colors.focusedPostconditionNode
      : Colors.focusedNode
    }
  },
  {
    selector: 'node[?error]',
    style: { 
      'border-width':'0px',
      'background-color': () => settings.showingErrors
      ? Colors.errorNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node[?spinning]',
    style: { 
      'shape' : 'vee',
      'width' : 50,
      'height' : 50,
      'background-color': () => settings.showingErrors
      ? Colors.errorNode
      : Colors.defaultNode
    }
  },
  {
    selector: 'node.pathHighlight[?error],node.pathHighlight[?spinning]',
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
      'border-width':'12px',
      'width' : 25,
      'height' : 25,
      'border-color': Colors.focusedNode,
      'underlay-padding':"15px"
    }
  },
  {
    //we don't display checks in CFG mode, since we don't really have
    //meaningful branches there.
    selector: 'node[?checked][^mergedIds]',
    style: {
      'label':'×',
      'font-size':'36px',
      'text-halign':'center',
      'text-valign':'center'
    }
  },
  {
    selector: 'node.pathHighlight[?checked]',
    style: {
      "color":"white"
    }
  }
]
