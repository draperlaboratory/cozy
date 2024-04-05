import { constraintsEq } from './constraints.js'

// We try to tidy up a given graph by merging non-branching series of nodes into single nodes

export function tidyGraph(graph, opts) {

  const root = graph.nodes().roots()

  tidyChildren(root, opts)

}

function tidyChildren(node, { mergeConstraints }) {

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
            id: `${parent.id()}-${out[0].id()}`, source: parent.id(), target: out[0].id()
          }
          node.cy().add({ group: 'edges', data: edgeData })
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

export function mergeByAddress(cy) {
  const constructed = {}
  for (const node of cy.nodes()) {
    const addr = node.data().address
    if (addr in constructed) {
      if (node.hasClass('pathHighlight')) constructed[addr].addClass('pathHighlight')
      node.cleanMe = true
    } else {
      constructed[addr] = node
    }
  }
  const startingEdges = [...cy.edges()]
  for (const edge of startingEdges) {
    if (!edge.source().cleanMe && !edge.target().cleanMe) {
      if (edge.hasClass("pathHighlight")) {
        edge.data("traversals", (edge.data("traversals") || 0) + 1)
      }
    } else {
      const sourceRepr = constructed[edge.source().data("address")]
      const targetRepr = constructed[edge.target().data("address")]
      if (sourceRepr.edgesTo(targetRepr).length > 0) {
        if (edge.hasClass("pathHighlight")) {
          const traversals = sourceRepr.edgesTo(targetRepr)[0].data("traversals")
          sourceRepr.edgesTo(targetRepr)[0].data("traversals", (traversals || 0) + 1)
        }
      } else {
        cy.add({
          group: 'edges',
          data: {
            source: sourceRepr.id(),
            target: targetRepr.id(),
            traversals: edge.hasClass("pathHighlight") ? 1 : 0
          }
        })
      }
      edge.remove()
    }
  }
  for (const node of cy.nodes()) {
    if (node.cleanMe) node.remove()
  }
  // this kinda mangles the styles, so we refresh them
  cy.style().update()
}
