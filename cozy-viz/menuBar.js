import { computePosition, flip } from 'https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm';
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'

// this should be mounted and unmounted rather than toggled; adding and removing
// the event-listener for closing the menu should be part of the mount/unmount
// lifecycle

class Menu extends Component {
  constructor() {
    super()
    this.button= createRef()
    this.options = createRef()
  }


  componentDidUpdate() {
    if (this.props.open == this.props.title) {
      computePosition(this.button.current, this.options.current, {
        placement: "bottom-start"
      }).then(({x,y}) => {
        this.options.current.style.left = `${x}px`
        this.options.current.style.top = `${y}px`
      })
    }
  }

  render(props) {
    const optionStyle = {
      position: "absolute",
      display: "block",
      backgroundColor: "#e1e1e1"
    }
    const menuStyle = {
      backgroundColor: props.open === props.title 
        ? "#e1e1e1" 
        : "white"
    }
    return html`
      <button 
        style=${menuStyle} 
        ref=${this.button} 
        onClick=${() => props.setOpen(props.title)}
        onMouseEnter=${() => props.open && props.setOpen(props.title)}>
        ${props.title}
      </button>
      ${props.open == props.title && html`
        <div style=${optionStyle} ref=${this.options} class="options-wrapper">
          ${props.children}
        </div>`
      }`
  }
}

function noMemoryDiffs(leaf, other) {
  const comparison = leaf.data().compatibilities[other.id()]
  if (Object.keys(comparison.memdiff).length) return false
  else return noErrors(leaf,other)
}

function noRegisterDiffs(leaf, other) {
  const comparison = leaf.data().compatibilities[other.id()]
  if (Object.keys(comparison.regdiff).length) return false
  else return noErrors(leaf,other)
}

function noErrors(leaf, other) {
  if (leaf.data().error || other.data().error) return false
  else return true
}

function noStdDiffs(leaf, other) {
  if (leaf.data().stdout != other.data().stdout ||
    leaf.data().stderr != other.data().stderr) return false
  else return noErrors(leaf,other)
}

export default class MenuBar extends Component {
  constructor() {
    super()
    this.state = {
      open: null,
    }
  }

  componentDidMount() {
    this.globalClickListener = ev => this.handleGlobalClick(ev)
    this.closeListener = () => this.setOpen(null)
    window.addEventListener("blur", this.closeListener)
    window.addEventListener("mousedown", this.globalClickListener)
  }

  componentWillUnmount() {
    window.removeEventListener("blur", this.closeListener)
    window.removeEventListener("mousedown", this.globalClickListener)
  }

  setOpen(open) {
    this.setState({open})
  }

  handleGlobalClick() {
    if (this.state.open) {
      this.setState({open: null})
    }
  }

  handleLocalClick(ev) {
    if (this.state.open) {
      ev.stopPropagation()
    }
  }

  prune(test) {
    this.props.prune(test)
    this.setOpen(null)
  }

  setTidiness(level) {
    this.props.setTidiness(level)
    this.setOpen(null)
  }

  resetLayout() {
    this.props.resetLayout()
    this.setOpen(null)
  }

  render(props, state) {
    return html`<div id="menubar"
        onMousedown=${ev => this.handleLocalClick(ev)}
      >
      <${Menu} open=${state.open}
        title="View"
        setOpen=${o => this.setOpen(o)}>
        <option 
          onClick=${() => this.setTidiness("untidy")}
          data-selected=${props.tidiness == "untidy"}>
            Show All Blocks
        </option>
        <option 
          onClick=${() => this.setTidiness("tidy")}
          data-selected=${props.tidiness == "tidy"}>
            Merge Unless Constaints Change
        </option>
        <option 
          onClick=${() => this.setTidiness("very-tidy")}
          data-selected=${props.tidiness == "very-tidy"}>
            Merge Unless Branching Occurs
        </option>
      <//>
      <${Menu} open=${state.open}
        title="Prune"
        setOpen=${o => this.setOpen(o)}>
        <option onClick=${() => this.prune(noMemoryDiffs)}>
            Completed Branches with Identical Memory
        </option>
        <option onClick=${() => this.prune(noRegisterDiffs)}>
            Completed Branches with Identical Register Contents 
        </option>
        <option onClick=${() => this.prune(noStdDiffs)}>
            Completed Branches with Identical Stdout/Stderr
        </option>
        <option onClick=${() => this.prune(noErrors)}>
            All Completed (Error-free) Branches
        </option>
      <//>
      <${Menu} open=${state.open}
        title="Layout"
        setOpen=${o => this.setOpen(o)}>
        <option onClick=${() => this.resetLayout()}>
            Reset
        </option>
      <//>
    </div>`
  }
}
