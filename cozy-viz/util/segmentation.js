import cytoscape from "https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm"

// given the top and bottom nodes, return a list of nodes in a segment
export function getNodesFromEnds(top, bottom) {
  const interval = [ bottom ]
  while (interval[ interval.length - 1 ].id() !== top.id()) {
    interval.push(interval[interval.length - 1].incomers("node")[0])
  }
  return interval
}

// given the top and bottom nodes, return a list of edges in a segment
export function getEdgesFromEnds(top, bottom) {
  const nodes = getNodesFromEnds(top, bottom)
  nodes.pop()
  return nodes.map(node => node.incomers("edge")[0])
}

// Given a top and bottom node, construct a new segment (cloning the original
// range), including edges
export class Segment {
  constructor(top, bot) {
    this.cy = cytoscape({
      elements: 
        bot.predecessors()
        .intersection(top.successors())
        .union(top)
        .union(bot)
        .jsons()
    })


    this.top = this.cy.nodes().roots()[0]
    this.bot = this.cy.nodes().leaves()[0]
    this.cy = () => bot.cy()
  }

  static fromRange(range) {
    const bot =  range.filter(ele => ele.outgoers("node").intersection(range).length == 0)[0]
    const top = range.filter(ele => ele.incomers("node").intersection(range).length == 0)[0]
    return new Segment(top, bot)
  }
}
