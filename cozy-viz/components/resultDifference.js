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
    const rslt_annotation_rows = []
    const annotations = props.leftFocus.bot.data().compatibilities[rightId]?.ret_annotation_diff
    console.log(annotations)
    const annotation_leaves = annotationToLeaves(annotations)

    if (state.view == "symbolic") for (const annotation of annotation_leaves) {
      if (annotation.tag === "leafNeq") rslt_annotation_rows.push(html`
        <span class="grid-diff-left">${annotation.left}</span>
        <span class="grid-diff-label">${annotation.path}</span>
        <span class="grid-diff-right">${annotation.right}</span>`)
      if (annotation.tag === "fieldEq") rslt_annotation_rows.push(html`
        <span class="grid-diff-left">${annotation.left}</span>
        <span class="grid-diff-label">${annotation.path}</span>
        <span class="grid-diff-right">${"Annotations logically Equivalent ✓"}</span>`)
    }

    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${0}/>
      ${annotations && html`<div id="grid-diff-data"> ${rslt_annotation_rows}</div>`}
      </div>`
  }
}
