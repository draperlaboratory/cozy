import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import ConcretionSelector from './concretionSelector.js'
import { symAnnotationToLeaves, concAnnotationToLeaves } from '../util/annotationToLeaves.js'

export default class MemoryDifference extends Component {
  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const address_rows = []
    const annotation_rows = []
    const conc_memdiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_memdiff ?? []
    const annotations = props.leftFocus.bot.data().compatibilities[rightId]?.annotation_diff
    const conc_annotations = props.leftFocus.bot.data().compatibilities[rightId]?.conc_annotation_diff
    const memdiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].memdiff
      : conc_memdiffs[state.view]
    const anno_diffs = state.view === "symbolic"
      ? symAnnotationToLeaves(annotations)
      : concAnnotationToLeaves(conc_annotations[state.view])

    for (const addr in memdiffs) {
      const addrparts = addr
        .split('\n')
        .map(part => [part, html`<br/>`])
        .flat()
      address_rows.push(html`
        <span class="grid-diff-left">${memdiffs[addr][0]}</span>
        <span class="grid-diff-label">${addrparts}</span>
        <span class="grid-diff-right">${memdiffs[addr][1]}</span>`)
    }

    for (const annotation of anno_diffs) {
      if (annotation.tag === "fieldEq") { 
        annotation_rows.push(html`
          <span class="grid-diff-left">${annotation.left}</span>
          <span class="grid-diff-label">${annotation.path}</span>
          <span class="grid-diff-right">${annotation.right} <strong>(equivalent)</strong></span>`)
      } else {
        annotation_rows.push(html`
          <span class="grid-diff-left">${annotation.left}</span>
          <span class="grid-diff-label">${annotation.path}</span>
          <span class="grid-diff-right">${annotation.right}</span>`)
      }
    }

    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_memdiffs.length}/>
      <div id="grid-diff-data"> ${address_rows.length > 0
        ? address_rows
        : html`<span class="no-difference">no memory differences detected ✓</span>`
      }</div>
      ${anno_diffs.length && html`<hr/><div id="grid-diff-data"> ${annotation_rows}</div>`}
      </div>`
  }
}
