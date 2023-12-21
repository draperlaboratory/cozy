// given the top and bottom nodes, return a list of nodes in a segment
export function getNodesFromEnds(top, bottom) {
  const interval = [ bottom ]
  while (interval[interval.length - 1 ] !== top) {
    interval.push(interval[interval.length - 1].incomers("node")[0])
  }
  return interval
}
