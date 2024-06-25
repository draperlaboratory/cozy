import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'

export default class ConcretionSelector extends Component {
  render(props) {

    if (props.concretionCount === 0) return null

    const buttons = [html`<button 
      data-selected=${props.view == "symbolic"} 
      onClick=${() => props.setView("symbolic")}
      >Symbolic</button>`
    ]

    for (let i = 0; i < props.concretionCount; i++) {
      buttons.push(html`<button 
        data-selected=${props.view == i} 
        onClick=${() => props.setView(i)}
        >Example ${i + 1}</button>`
      )
    }

    return html`<div class="subordinate-buttons">${buttons}</div>`
  }
}
