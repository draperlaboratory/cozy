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
}

export const style = [
  { 
    selector: "node",
    style: {
      // 'background-image': (ele) => { return makeSvg(ele).svg },
      // 'width': (ele) => { return makeSvg(ele).width},
      // 'height': (ele) => { return makeSvg(ele).height},
      'shape': 'round-rectangle',
      'background-color': elt => {
        if (elt.data().error) {
          return "#facdcd"
        } else if (elt.data().simprocs.length > 0 && settings.showingSimprocs) {
          return '#f7be6d'
        } else if (elt.data().has_syscall && settings.showingSyscalls) {
          return '#add8e6'
        } else {
          return '#ededed'
        }
      },
      'border-color': '#ccc',
      'border-width': elt => {
        if (elt.outgoers().length == 0 && !elt.data().error) {
          return '5px'
        } else {
          return '0px'
        }
      }
    },
  },
  {
    selector: 'edge',
    style: {
      'width': 3,
      'line-color': '#ccc',
      'target-arrow-color': '#ccc',
      'target-arrow-shape': 'triangle',
      // 'arrow-scale': '2',
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
      // 'arrow-scale': '2',
      'curve-style': 'bezier'
    }
  },
  {
    selector: 'node.pathHighlight',
    style: {
      'border-width':'0px',
      'background-color': (elt) => {
        if (elt.data().error) {
          return "#d00"
        } else {
          return '#666'
        }
      },
    }
  },
  {
    selector: 'node.simprocs',
    style: { 'border-color': '#f7be6d' }
  },
  {
    selector: 'node.availablePath',
    style: {
      'border-width':'5px',
      'border-color': '#666'
    }
  },
]
