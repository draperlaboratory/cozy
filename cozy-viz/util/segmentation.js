import {constraintsEq} from './constraints.js'

export const segmentationMixin = {

  // XXX: It would be possible to memoize on constraints here, but that adds
  // some complexity when the granularity of the graph changes
  getSegment(node) {
    const constraints =  node.data().constraints

    // first we ascend to the highest node with the given constraints
    let target = node
    while (target.incomers('node').length == 1 && 
      constraintsEq(constraints, target.incomers('node')[0].data().constraints)) {
      target = target.incomers('node')[0]
    }

    // then we descend, assembling the relevant nodes
    let generations = [[target]]
    while (true) {
      const lastGen = generations[generations.length - 1]
      const nextGen = lastGen.flatMap(n => 
        n.outgoers('node')
         .filter(o => constraintsEq(o.data().constraints, constraints))
         .toArray()
      )
      if (nextGen.length > 0) generations.push(nextGen)
      else break
    }

    generations = generations.flat()

    return this.collection(generations)
  },

  showSegment(node) {
    const seg = this.getSegment(node)
    this.elements().removeClass("segmentHighlight")
    seg.addClass("segmentHighlight")
  },

  // gets all leaves in cy compatible with a given
  // node
  getLeavesCompatibleWith(node, cy) {
    const leaves = node.successors().add(node).leaves()
    const ids = leaves.flatMap(leaf => Object.keys(leaf.data().compatibilities))
      .map(s => `#${s}`)
    const compats = []
    for (const id of ids) {
      compats.push(cy.$(id)[0])
    }
    return compats
  },

  // in a preorder, find the greatest element p such that each element of leaves
  // is > p; i.e the strongest set of constraints implied by the constraints on
  // each member of leaves
  getMinimalCeiling(leaves) {
    let depth = 1;
    const canonicalPreds = leaves[0].predecessors('node')
    while (true) for (const leaf of leaves) {
      // only look up once per loop. Could be much further optimized.
      const preds = leaf.predecessors('node')
      if (depth >= preds.length) {
        return leaf 
      } else if (preds[preds.length - depth] !== canonicalPreds[canonicalPreds.length - depth]) {
        return canonicalPreds[canonicalPreds.length - (depth - 1)]
      } else {
        depth += 1
      }
    }
  }
}
