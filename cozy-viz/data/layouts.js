export const breadthFirst = {
  name: 'breadthfirst',
  directed: true,
  spacingFactor: 2
}

export const cola = {
  name: 'cola',
}

export const cose = {
  name: 'cose',
  nodeRepulsion: function () { return 10000},
  idealEdgeLength: function(){ return 64 },
  edgeElasticity: function( ){ return 128; },
}
