import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import ConcretionSelector from './concretionSelector.js'

export default class MemoryDifference extends Component {
  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const addresses = []
    const conc_adiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_memdiff ?? []
    const adiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].memdiff
      : conc_adiffs[state.view]
    for (const addr in adiffs) {
      const addrparts = addr
        .split('\n')
        .map(part => [part, html`<br/>`])
        .flat()
      addresses.push(html`
        <span class="grid-diff-left">${adiffs[addr][0]}</span>
        <span class="grid-diff-label">${addrparts}</span>
        <span class="grid-diff-right">${adiffs[addr][1]}</span>`)
    }
    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_adiffs.length}/>
      <div id="grid-diff-data"> ${addresses.length > 0
        ? addresses
        : html`<span class="no-difference">no memory differences detected ✓</span>`
      }</div></div>`
  }
}
