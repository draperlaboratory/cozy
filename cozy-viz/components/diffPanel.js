import * as Diff from 'https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm'
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'

export default class DiffPanel extends Component {
  constructor() {
    super();
    this.state = {
      mode: null,
    }
  }

  toggleMode(mode) {
    if (this.state.mode == mode) {
      this.setState({mode:null})
    } else {
      this.setState({mode})
    }
  }

  setLeftFocus(leftFocus) {
    this.setState({leftFocus})
    if (this.state.rightFocus) this.diffAssemblyWith(leftFocus, this.state.rightFocus)
  }

  setRightFocus(rightFocus) {
    this.setState({rightFocus})
    if (this.state.leftFocus) this.diffAssemblyWith(this.state.leftFocus,rightFocus)
  }

  setBothFoci(leftFocus, rightFocus) {
    this.setState({ leftFocus, rightFocus })
    this.diffAssemblyWith(leftFocus,rightFocus);
  }

  resetLeftFocus(leftFocus) {
    this.setState({
      rightFocus:null,
      rightAssemblyDiff:null,
      leftAssemblyDiff:null, 
      leftFocus})
  }

  resetRightFocus(rightFocus) {
    this.setState({
      leftFocus:null,
      rightAssemblyDiff:null,
      leftAssemblyDiff:null, 
      rightFocus})
  }

  resetBothFoci() {
    this.setState({
      leftFocus:null,
      rightFocus:null,
      rightAssemblyDiff:null,
      leftAssemblyDiff:null, 
      })
  }

  diffAssemblyWith(leftFocus,rightFocus) {
    const leftLines = leftFocus.data().assembly.split('\n')
    const rightLines = rightFocus.data().assembly.split('\n')
    const diffs = Diff.diffLines(leftFocus.data().assembly, rightFocus.data().assembly, {
      comparator(l,r) { return l.substring(6) == r.substring(6) }
    })
    let renderedRight = []
    let renderedLeft = []
    let curLeft = 0
    let curRight = 0
    for (const diff of diffs) {
      let hunkRight
      let hunkLeft
      if (diff?.added) {
        hunkRight = html`<span class="hunkAdded">${diff.value}</span>`
        hunkLeft = html`<span>${Array(diff.count).fill('\n').join("")}</span>`
        curRight += diff.count
      } else if (diff?.removed) {
        hunkLeft = html`<span class="hunkRemoved">${diff.value}</span>`
        hunkRight = html`<span>${Array(diff.count).fill('\n').join("")}</span>`
        curLeft += diff.count
      } else {
        const leftPiece = []
        const rightPiece = []
        for (let i = 0; i < diff.count; i++) {
          leftPiece.push(leftLines[curLeft] + '\n')
          rightPiece.push(rightLines[curRight] + '\n')
          curRight++
          curLeft++
        }
        hunkRight = html`<span>${rightPiece}</span>`
        hunkLeft = html`<span>${leftPiece}</span>`
      }
      renderedRight.push(hunkRight)
      renderedLeft.push(hunkLeft)
    }
    this.setState({
      leftAssemblyDiff: renderedLeft,
      rightAssemblyDiff: renderedRight,
    })
  }

  getLeftFocusAssembly() {
    return this.state.leftAssemblyDiff || this.state.leftFocus?.data().assembly
  }

  getRightFocusAssembly() {
    return this.state.rightAssemblyDiff || this.state.rightFocus?.data().assembly
  }

  render(props, state) {
    const assemblyAvailable = state.leftFocus || state.rightFocus
    const registersAvailable = state.leftFocus && state.rightFocus &&
      state.leftFocus.data().compatibilities[state.rightFocus.id()].regdiff
    const memoryAvailable = state.leftFocus && state.rightFocus &&
      state.leftFocus.data().compatibilities[state.rightFocus.id()].memdiff
    const concretionAvailable = state.leftFocus && state.rightFocus &&
      state.leftFocus.data().compatibilities[state.rightFocus.id()].conc_args
    return html`<div id="diff-panel" onMouseEnter=${props.onMouseEnter}>
      <div>
        <button 
          disabled=${!assemblyAvailable}
          onClick=${() => this.toggleMode("assembly")}>
          Assembly
        </button>
        <button 
          disabled=${!memoryAvailable}
          onClick=${() => this.toggleMode("memory")}>
          Memory
        </button>
        <button disabled=${!registersAvailable}
          onClick=${() => this.toggleMode("registers")}>
          Registers
        </button>
        <button disabled=${!concretionAvailable}
          onClick=${() => this.toggleMode("concretions")}>
          Concretions
        </button>
      </div>
      ${state.mode == "assembly" && assemblyAvailable && html`
        <div id="asm-diff-data">
          <pre id="asmViewLeft">
          ${this.getLeftFocusAssembly()}
          </pre>
          <pre id="asmViewRight">
          ${this.getRightFocusAssembly()}
          </pre>
        </div>`
      }
      ${state.mode == "registers" && registersAvailable && html`
          <${RegisterDifference} rightFocus=${state.rightFocus} leftFocus=${state.leftFocus}/>`
      }
      ${state.mode == "memory" && memoryAvailable && html`
          <${MemoryDifference} rightFocus=${state.rightFocus} leftFocus=${state.leftFocus}/>`
      }
      ${state.mode == "concretions" && concretionAvailable && 
          html`<${Concretions} rightFocus=${state.rightFocus} leftFocus=${state.leftFocus}/>`
      }
      </div>`
  }
}

class RegisterDifference extends Component {

  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  setView(view) {
    this.setState({view})
  }

  render(props, state) {
    const rightId = props.rightFocus.id()
    const registers = []
    const conc_regdiffs = props.leftFocus.data().compatibilities[rightId].conc_regdiff ?? []
    const rdiffs = state.view === "symbolic"
      ? props.leftFocus.data().compatibilities[rightId].regdiff
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
        setView=${view => this.setView(view)} 
        concretionCount=${conc_regdiffs.length}/>
      <div id="grid-diff-data"> ${registers.length > 0 
        ? registers
        : html`<span class="no-difference">no register differences detected ✓</span>`
      }</div></div>`
  }
}

class MemoryDifference extends Component {

  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  setView(view) {
    this.setState({view})
  }

  render(props, state) {
    const rightId = props.rightFocus.id()
    const addresses = []
    const conc_adiffs = props.leftFocus.data().compatibilities[rightId].conc_memdiff ?? []
    const adiffs = state.view === "symbolic"
      ? props.leftFocus.data().compatibilities[rightId].memdiff
      : conc_adiffs[state.view]
    for (const reg in adiffs) {
      addresses.push(html`
        <span class="grid-diff-left">${adiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${adiffs[reg][1]}</span>`)
    }
    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setView(view)} 
        concretionCount=${conc_adiffs.length}/>
      <div id="grid-diff-data"> ${addresses.length > 0 
        ? addresses
        : html`<span class="no-difference">no memory differences detected ✓</span>`
      }</div></div>`
  }
}

class Concretions extends Component {
  render(props) {
    const rightId = props.rightFocus.id()
    const examples = []
    const concretions = props.leftFocus.data().compatibilities[rightId].conc_args
    for (const concretion of concretions) {
      examples.push(html`
        <pre class="concrete-example">${JSON.stringify(concretion, undefined, 2)}</pre>
      `)
    }
    return html`<div id="concretion-header">
      Viewing ${concretions.length} concrete input examples
    </div>
    <div id="concretion-data">
      ${examples}
    </div>`
  }
}

class ConcretionSelector {
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
