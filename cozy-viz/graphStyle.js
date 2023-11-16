// const makeSvg = (ele) => {
//   const parser = new DOMParser();
//   const theText = ele.data().contents;
//   const width = 400
//   const height = Math.min(400, theText.split("\n").length * 15 + 80)
//   let svgText =
//     `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg><svg xmlns='http://www.w3.org/2000/svg' version='1.1' width='${width}' height='${height}'>
//     <foreignObject x="20" y="20" width="${width}" height="${height}">
//     <pre style="font-family:monospace" xmlns="http://www.w3.org/1999/xhtml">${theText}</pre>
//     </foreignObject>
//     </svg>`;
//   return {
//     svg: 'data:image/svg+xml;utf8,' + encodeURIComponent(parser.parseFromString(svgText, 'text/xml').documentElement.outerHTML),
//     height,
//     width
//   }
// };

export const settings = {
  showingSimprocs: true,
  showingSyscalls: true,
  showingErrors: true,
}

export const style = [
  { 
    selector: "node",
    style: {
      'shape': 'round-rectangle',
      'background-color': '#ededed',
      'border-color': '#ccc',
    },
  },
  { 
    selector: "[[outdegree = 0]][!error]",
    style: { 'border-width': '5px' },
  },
  {
    selector: 'edge',
    style: {
      'width': 3,
      'line-color': '#ccc',
      'target-arrow-color': '#ccc',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier'
    }
  },
  {
    selector: 'edge.pathHighlight',
    style: {
      'width': 3,
      'line-color': '#666',
      'target-arrow-color': '#666',
      'target-arrow-shape': 'triangle',
      'z-compound-depth' : 'top',
      'curve-style': 'bezier'
    }
  },
  {
    selector: 'node.pathHighlight',
    style: { 'background-color': '#666' }
  },
  {
    selector: 'node[?has_syscall]',
    style: { 'background-color': () => settings.showingSyscalls
      ? '#add8e6'
      : '#ededed'
    }
  },
  {
    selector: 'node[simprocs.length > 0]',
    style: { 'background-color': () => settings.showingSimprocs
      ? '#f7be6d'
      : '#ededed'
    }
  },
  {
    selector: 'node[?error]',
    style: { 'background-color': "#facdcd" }
  },
  {
    selector: 'node.pathHighlight[?error]',
    style: {
      'border-width':'0px',
      'background-color': "#d00"
    }
  },
  {
    selector: 'node.availablePath',
    style: {
      'border-width':'5px',
      'border-color': '#666'
    }
  },
]
