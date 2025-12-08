import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import ConcretionSelector from './concretionSelector.js'
import { symAnnotationToLeaves, concAnnotationToLeaves } from '../util/annotationToLeaves.js'

export default class ReturnDifference extends Component {
  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const annotation_rows = []
    const annotations = props.leftFocus.bot.data().compatibilities[rightId]?.ret_annotation_diff
    const conc_annotations = props.leftFocus.bot.data().compatibilities[rightId]?.conc_ret_annotation_diff
    const anno_diffs = state.view === "symbolic"
      ? symAnnotationToLeaves(annotations)
      : concAnnotationToLeaves(conc_annotations[state.view])

    for (const annotation of anno_diffs) {
      const path = /root\.(.*)/.exec(annotation.path)[1] ?? annotation.path
      if (annotation.tag === "fieldEq") { 
        annotation_rows.push(html`
          <span class="grid-diff-left">${annotation.left}</span>
          <span class="grid-diff-label">${path}</span>
          <span class="grid-diff-right">${annotation.right} <strong>(equivalent)</strong></span>`)
      } else {
        annotation_rows.push(html`
          <span class="grid-diff-left">${annotation.left}</span>
          <span class="grid-diff-label">${path}</span>
          <span class="grid-diff-right">${annotation.right}</span>`)
      }
    }

    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_annotations.length}/>
      ${annotations && html`<div id="grid-diff-data"> ${annotation_rows}</div>`}
      </div>`
  }
}
