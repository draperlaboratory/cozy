import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import Concretions from './concretions.js'
import ActionDifference from './actionDifference.js'
import AssemblyDifference from './assemblyDifference.js'
import RegisterDifference from './registerDifference.js'
import MemoryDifference from './memoryDifference.js'
import SideEffectDifference from './sideEffectDifference.js'

export default class DiffPanel extends Component {
  constructor() {
    super();
    this.state = {
      mode: null,
    }

    this.diffPanel = createRef()
    this.dragHandle = createRef()
  }

  toggleMode(mode) {
    if (this.state.mode == mode) {
      this.setState({ mode: null })
    } else {
      this.setState({ mode })
    }
  }

  startResize(e) {
    this.diffPanel.current.onpointermove = e => {
      this.diffPanel.current.style.maxHeight = `${Math.max(50, window.innerHeight - e.clientY)}px`
    }
    this.dragHandle.current.setPointerCapture(e.pointerId)
    this.dragHandle.current.classList.add("grabbed")
    this.diffPanel.current.classList.add("resizing")
  }

  stopResize(e) {
    this.diffPanel.current.onpointermove = null
    this.dragHandle.current.releasePointerCapture(e.pointerId)
    this.dragHandle.current.classList.remove("grabbed")
    this.diffPanel.current.classList.remove("resizing")
  }

  render(props, state) {
    const assemblyAvailable = props.leftFocus || props.rightFocus
    const registersAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.regdiff
    const memoryAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.memdiff
    const concretionAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.conc_args
    const actionsAvailable =
      props.rightFocus?.top.outgoers("edge")[0]?.data('actions')?.length > 0 ||
      props.leftFocus?.top.outgoers("edge")[0]?.data('actions')?.length > 0
    const sideEffectsAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.conc_sediff
    return html`<div id="diff-panel" onMouseEnter=${props.onMouseEnter} ref=${this.diffPanel}>
      <div id="diff-drag-handle"
        onPointerDown=${e => this.startResize(e)} 
        onPointerUp=${e => this.stopResize(e)} 
        ref=${this.dragHandle}
      />
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
        <button disabled=${!actionsAvailable}
          onClick=${() => this.toggleMode("actions")}>
          Events
        </button>
        <button disabled=${!sideEffectsAvailable}
          onClick=${() => this.toggleMode("side-effects")}>
          Side Effects
        </button>
      </div>
      ${state.mode == "assembly" && assemblyAvailable && html`
        <${AssemblyDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "registers" && registersAvailable && html`
        <${RegisterDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "memory" && memoryAvailable && html`
        <${MemoryDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "concretions" && concretionAvailable && html`
        <${Concretions} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "actions" && actionsAvailable && html`
        <${ActionDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "side-effects" && sideEffectsAvailable && html`
        <${SideEffectDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      </div>`
  }
}
