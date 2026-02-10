import {constraintsEq} from './constraints.js'

export const segmentationMixin = {

  // XXX: It would be possible to memoize on constraints here, but that adds
  // some complexity when the granularity of the graph changes
  // 
  // The connector is an extra function that we can use to potentially link
  // segments with different constraints under some conditions
  getRangeOf(node, connector) {
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
         .filter(outgoer => {
           if (constraintsEq(outgoer.data().constraints, n.data().constraints)) return true
           if (connector?.(outgoer, n)) return true
         })
         .toArray()
      )
      if (nextGen.length > 0) generations.push(nextGen)
      else break
    }

    generations = generations.flat()

    return this.collection(generations)
  },

  segmentToRange(segment) {
    return segment.bot.predecessors('node')
      .intersection(segment.top.successors('node'))
      .union(segment.top)
      .union(segment.bot)
  },

  rangeToSegment(range) {
    return {
      bot: range.filter(ele => ele.outgoers("node").intersection(range).length == 0)[0],
      top: range.filter(ele => ele.incomers("node").intersection(range).length == 0)[0],
    }
  },

  // this shows a generalized segment, in which we ignore additional
  // constraints that don't narrow the pool of compatible nodes on the opposite
  // side.
  getCompatibilityRangeOf(node, cy) {
    const connector = (n,o) => {
      const ncompat = this.getLeavesCompatibleWith(n,cy)
      const ocompat = this.getLeavesCompatibleWith(o,cy)
      return ncompat.size == ocompat.size
    }
    return this.getRangeOf(node, connector)
  },

  // gets all leaves in cy compatible with a given node
  //
  // XXX : this should probably be disabled when pruning is in progress, it
  // doesn't necessarily make sense once nodes have been removed.
  getLeavesCompatibleWith(node, cy) {
    const leaves = node.successors().add(node).leaves()
    const ids = leaves.flatMap(leaf => Object.keys(leaf.data().compatibilities))
      .map(s => `#${s}`)
    const compats = new Set()
    for (const id of ids) {
      compats.add(cy.$(id)[0])
    }
    return compats
  },

  // in a preorder, find the greatest/lowest element p such that each element of leaves
  // is > p; i.e the strongest set of constraints implied by the constraints on
  // each member of leaves
  getMinimalCeiling(leaves) {
    let depth = 1;
    const [canonicalLeaf] = leaves
    const canonicalPreds = canonicalLeaf.predecessors('node')
    // If there's only one leaf, it's the strongest thing that is implied by each member of leaves
    if (leaves.size === 1) return canonicalLeaf
    // Otherwise, we walk down the predecessors from the root of the tree until
    // we hit a place where the predecessors of one of our leaves separates
    // from our canonical list of predecessors or run out of predecessors
    // (which happens if the fork is right above a leaf) and then back up one.
    while (true) { 
      for (const leaf of leaves) {
        // only look up once per loop. Could be much further optimized.
        const preds = leaf.predecessors('node')
        if (depth > preds.length || preds[preds.length - depth] !== canonicalPreds[canonicalPreds.length - depth]) {
          return canonicalPreds[canonicalPreds.length - (depth - 1)]
        }
      } 
      depth += 1
    }
  },
}
