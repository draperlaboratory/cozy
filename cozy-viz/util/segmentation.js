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
    while (generations.length < 10) {
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
  }
}
