import { constraintsEq } from './constraints.js'

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

export const tidyMixin = {
  // array of graph elements merged out of existence
  mergedNodes : [],
  mergedEdges : [],

  // We try to tidy up a given graph by merging non-branching series of nodes
  // into single nodes
  tidy(opts) {

    const root = this.nodes().roots()

    tidyChildren(root, opts)

  },
  //merge blocks that share an address
  mergeByAddress() {
    const constructed = {}
    this.mergedNodes = []
    this.mergedEdges = []
    for (const node of this.nodes()) {
      this.tidyStdOut(node)
    }
    for (const node of this.nodes()) {
      const addr = node.data().address
      if (addr in constructed) {
        this.mergedNodes.push(node)
        const priorStdout = constructed[addr].data('newStdout')
        if (priorStdout.length > 0) {
          constructed[addr].data('stdout', priorStdout + '\n--\n' + node.data('newStdout'))
        }
      } else {
        this.removePlainData(node)
        node.data('stdout', node.data('newStdout'))
        constructed[addr] = node
      }
      if (node.hasClass('pathHighlight')) constructed[addr].data('traversed', true)
      if (node.incomers().length == 0) constructed[addr].data('initial', true)
      if (node.outgoers().length == 0) constructed[addr].data('terminal', true)
    }
    const startingEdges = [...this.edges()]
    for (const edge of startingEdges) {
      const sourceRepr = constructed[edge.source().data("address")]
      const targetRepr = constructed[edge.target().data("address")]
      if ( edge.source() == sourceRepr && edge.target() == targetRepr ) {
        if (edge.hasClass("pathHighlight")) {
          edge.data("traversals", (edge.data("traversals") || 0) + 1)
        }
      } else {
        if (sourceRepr.edgesTo(targetRepr).length > 0) {
          if (edge.hasClass("pathHighlight")) {
            const traversals = sourceRepr.edgesTo(targetRepr)[0].data("traversals")
            sourceRepr.edgesTo(targetRepr)[0].data("traversals", (traversals || 0) + 1)
          }
        } else {
          this.add({
            group: 'edges',
            data: {
              source: sourceRepr.id(),
              target: targetRepr.id(),
              traversals: edge.hasClass("pathHighlight") ? 1 : 0
            }
          })
        }
        this.mergedEdges.push(edge)
      }
    }
    for (const element of [...this.mergedNodes, ...this.mergedEdges]) {
      element.remove()
    }
    // this kinda mangles the styles, so we refresh them
    this.style().update()
  },

  // remove data that doesn't make sense in the CFG context
  removePlainData(node) {
    node.removeData('constraints')
    node.removeData('stdout')
    node.removeData('stderr')
  },

  // take a node from a tree, and derive what is *new* at that node
  tidyStdOut(node) {
    if (node.incomers('node').length == 1) {
      const incomerStdout = node.incomers('node')[0].data('stdout')
      console.log(incomerStdout)
      node.data('newStdout', node.data('stdout').slice(incomerStdout.length, Infinity))
    } else {
      node.data('newStdout', node.data('stdout'))
    }
  },

  // tidy extraneous data added to existing elements by merging. Constructed
  // nodes are removed automatically.
  removeCFGData() {
    let element
    while (element = this.mergedNodes.pop()) {
      element.restore()
    }
    while (element = this.mergedEdges.pop()) {
      element.restore()
    }
    for (const node of this.nodes()) {
      node.removeData("traversed")
      node.removeData("initial")
      node.removeData("terminal")
    }
    for (const edge of this.edges()) {
      edge.removeData("traversals")
    }
  }
}
