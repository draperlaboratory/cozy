import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'

export function hunkFormat(hunk, className) {
  const terminator = hunk.slice(-1)
  if (terminator === '>' || terminator == ',') {
    const newHunk = hunk.slice(0, hunk.length - 1)
    return html`<span class=${className}>${newHunk}</span>${terminator} `
  } else {
    return html`<span class=${className}>${hunk}</span> `
  }
}


export function Hunk({ dim, highlight, hunkCtx, curLeft, curRight, leftContent, leftClass, rightContent, rightClass }) {
  const hunk = html`<div
        onMouseEnter=${highlight} 
        onMouseLeave=${dim}
        >
        <div
          title=${hunkCtx?.leftMsgs[curLeft]}
          class=${leftClass}
        >${leftContent}</div>
        <div
          title=${hunkCtx?.rightMsgs[curRight]}
          class=${rightClass}
        >${rightContent}</div>
      </div>`

  hunk.contentListing = { left: leftContent, right: rightContent }

  return hunk
}
