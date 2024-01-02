// given the top and bottom nodes, return a list of nodes in a segment
export function getNodesFromEnds(top, bottom) {
  const interval = [ bottom ]
  while (interval[interval.length - 1 ] !== top) {
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
