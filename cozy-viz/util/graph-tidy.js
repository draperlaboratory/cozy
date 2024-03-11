import {constraintsEq} from './constraints.js'

// We try to tidy up a given graph by merging non-branching series of nodes into single nodes

export function tidyGraph(graph, opts) {

  const root = graph.nodes().roots()

  tidyChildren(root, opts)

}

function tidyChildren(node, {mergeConstraints}) {

  let candidates = [node];
  let next = [];

  while (candidates.length > 0) {
    for (const candidate of candidates) {
      const out = candidate.outgoers('node') 
      const constraints1 = out[0]?.data().constraints
      const constraints2 = candidate.data().constraints
      // We merge nodes with their children if they have exactly one child and either
      // A. the child has the same constraints, or 
      // B. we've enabled constraint merging
      if (out.length == 1 && (mergeConstraints || constraintsEq(constraints1, constraints2))) {
        // we accumulate the assembly, into the child
        out[0].data().contents = candidate.data().contents + '\n' + out[0].data().contents
        /// we accumulate vex, if there is any, into the child
        if (candidate.data().vex) {
          out[0].data().vex = candidate.data().vex + '\n' + out[0].data().vex
        }
        /// we accumulate has_syscall, if defined, into the child
        if ("has_syscall" in candidate.data()) {
          out[0].data().has_syscall |= candidate.data().has_syscall
        }
        /// we accumulate simprocs, if defined, into the child
        if (candidate.data().simprocs) {
          out[0].data().simprocs.unshift(...candidate.data().simprocs)
        }
        // introduce edges linking the child to its grandparent
        for (const parent of candidate.incomers('node')) {
          const edgeData = { 
            id : `${parent.id()}-${out[0].id()}`, source: parent.id(), target: out[0].id()
          }
          node.cy().add({group:'edges', data: edgeData})
        }
        // we remove the merge-candidate node
        candidate.remove()
        next.push(out[0])
      } else {
        for (const baby of out) {
          next.push(baby)
        }
      }
    }
    candidates = next
    next = []
  }
}

//remove a branch by consuming its root and parents until you reach a parent
//that has more than one child
export function removeBranch(node) {
  let target
  while (node.outgoers('node').length == 0 && 
    node.incomers('node').length > 0) {

    target = node
    node = node.incomers('node')[0]
    target.remove()
  }
  if (target &&
    node.outgoers('node').length == 0 && 
    node.incomers('node').length == 0) {
    node.remove()
  }
    
}
