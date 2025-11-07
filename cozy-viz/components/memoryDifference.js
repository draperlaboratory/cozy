import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import ConcretionSelector from './concretionSelector.js'
import { annotationToLeaves } from '../util/annotationToLeaves.js'

export default class MemoryDifference extends Component {
  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const address_rows = []
    const annotation_rows = []
    const conc_adiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_memdiff ?? []
    const annotations = props.leftFocus.bot.data().compatibilities[rightId]?.annotation_diff
    const annotation_leaves = annotationToLeaves(annotations)
    const adiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].memdiff
      : conc_adiffs[state.view]

    for (const addr in adiffs) {
      const addrparts = addr
        .split('\n')
        .map(part => [part, html`<br/>`])
        .flat()
      address_rows.push(html`
        <span class="grid-diff-left">${adiffs[addr][0]}</span>
        <span class="grid-diff-label">${addrparts}</span>
        <span class="grid-diff-right">${adiffs[addr][1]}</span>`)
    }

    if (state.view == "symbolic") for (const annotation of annotation_leaves) {
      if (annotation.tag === "leafNeq") annotation_rows.push(html`
        <span class="grid-diff-left">${annotation.left}</span>
        <span class="grid-diff-label">${annotation.path}</span>
        <span class="grid-diff-right">${annotation.right}</span>`)
      if (annotation.tag === "fieldEq") annotation_rows.push(html`
        <span class="grid-diff-left">${annotation.left}</span>
        <span class="grid-diff-label">${annotation.path}</span>
        <span class="grid-diff-right">${"Annotations logically Equivalent ✓"}</span>`)
    }

    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_adiffs.length}/>
      <div id="grid-diff-data"> ${address_rows.length > 0
        ? address_rows
        : html`<span class="no-difference">no memory differences detected ✓</span>`
      }</div>
      ${annotations && html`<hr/><div id="grid-diff-data"> ${annotation_rows}</div>`}
      </div>`
  }
}
