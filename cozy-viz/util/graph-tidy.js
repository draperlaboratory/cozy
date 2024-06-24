import { constraintsEq } from './constraints.js'


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
  mergedNodes: [],
  mergedEdges: [],

  // We try to tidy up a given graph by merging non-branching series of nodes
  // into single nodes
  tidy(opts) {

    const root = this.nodes().roots()

    this.tidyChildren(root, opts)

  },

  tidyChildren(node, { mergeConstraints }) {

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
          if (candidate.data("has_syscall")) {
            out[0].data().has_syscall |= candidate.data().has_syscall
          }
          /// we accumulate simprocs, if defined, into the child
          if (candidate.data("simprocs")) {
            out[0].data().simprocs.unshift(...candidate.data().simprocs)
          }
          if (candidate.data("actions")) {
            if (out[0].outgoers('edge').length) for (const edge of out[0].outgoers('edge')) {
              // we accoumulate actions into the child by putting them into its outgoing edges
              edge.data('actions', candidate.outgoers('edge')[0].data('actions').concat(edge.data('actions')))
            } else {
              // unless it has no outgoing edges, in which case we accumulate them into the node itelf
              out[0].data('actions', candidate.outgoers('edge')[0].data('actions'))
            }
          }
          // introduce edges linking the child to its grandparent
          for (const parent of candidate.incomers('node')) {
            const edgeData = {
              id: `${parent.id()}-${out[0].id()}`, 
              source: parent.id(), 
              target: out[0].id(),
              // we copy the relevant actions (those associated with the grandparent) into the new edge
              actions: candidate.incomers('edge').data('actions')
            }
            node.cy().add({ group: 'edges', data: edgeData })
          }
          // if the candidate is the root of a focused segment, the child becomes
          // the new root
          if (this.root?.id() == candidate.id()) {
            this.root = out[0]
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
        // node is already represented 
        this.mergedNodes.push(node)
        // so we mark it as merged
        const priorStdout = constructed[addr].data('newStdout')
        if (priorStdout.length > 0) {
          constructed[addr].data('stdout', priorStdout + '\n--\n' + node.data('newStdout'))
        }
        constructed[addr].data('mergedIds', `${constructed[addr].data('mergedIds')}${node.id()}#`)
        // and merge its stdout, and id with the representation
      } else {
        // node isn't represented
        this.removePlainData(node)
        node.data('stdout', node.data('newStdout'))
        node.data('mergedIds', `#${node.id()}#`)
        constructed[addr] = node
        // so we touch it up a bit and add it to the CFG
      }
      if (node.hasClass('pathHighlight')) constructed[addr].data('traversed', true)
      if (node.incomers().length == 0) constructed[addr].data('initial', true)
      if (node.outgoers().length == 0) constructed[addr].data('terminal', true)
    }
    const startingEdges = [...this.edges()]
    for (const edge of startingEdges) {
      const sourceRepr = constructed[edge.source().data("address")]
      const targetRepr = constructed[edge.target().data("address")]
      if (edge.source() == sourceRepr && edge.target() == targetRepr) {
        if (edge.hasClass("pathHighlight")) {
          edge.data("traversals", (edge.data("traversals") || 0) + 1)
        }
        edge.data('mergedIds', `#${edge.id()}#`)
      } else {
        if (sourceRepr.edgesTo(targetRepr).length > 0) {
          if (edge.hasClass("pathHighlight")) {
            const traversals = sourceRepr.edgesTo(targetRepr)[0].data("traversals")
            sourceRepr.edgesTo(targetRepr)[0]
              .data("traversals", (traversals || 0) + 1)
              .data("mergedIds", `${sourceRepr.edgesTo(targetRepr)[0].data('mergedIds')}${edge.id()}#`)
          }
        } else {
          this.add({
            group: 'edges',
            data: {
              source: sourceRepr.id(),
              target: targetRepr.id(),
              mergedIds: `#${edge.id()}#`,
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
      node.removeData("mergedIds")
    }
    for (const edge of this.edges()) {
      edge.removeData("traversals")
      edge.removeData("mergedIds")
    }
  }
}
