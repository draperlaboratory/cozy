import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import ConcretionSelector from './concretionSelector.js'

export default class RegisterDifference extends Component {

  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const registers = []
    const conc_regdiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_regdiff ?? []
    const rdiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].regdiff
      : conc_regdiffs[state.view]
    for (const reg in rdiffs) {
      registers.push(html`
        <span class="grid-diff-left">${rdiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${rdiffs[reg][1]}</span>`)
    }
    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_regdiffs.length}/>
      <div id="grid-diff-data"> ${registers.length > 0
        ? registers
        : html`<span class="no-difference">no register differences detected ✓</span>`
      }</div></div>`
  }
}

