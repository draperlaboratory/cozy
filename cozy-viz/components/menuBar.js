import { computePosition } from 'https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm';
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import { Status, Tidiness } from '../data/cozy-data.js'
import Colors from '../data/colors.js'

// this should be mounted and unmounted rather than toggled; adding and removing
// the event-listener for closing the menu should be part of the mount/unmount
// lifecycle

class Menu extends Component {
  constructor() {
    super()
    this.button = createRef()
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

  toggleOpen() {
    if (!this.props.enabled) return
    if (this.props.open != this.props.title) {
      this.props.setOpen(this.props.title)
    } else {
      this.props.setOpen(null)
    }
  }

  render(props) {
    const optionStyle = {
      position: "absolute",
      display: "block",
      backgroundColor: "#e1e1e1"
    }
    const menuStyle = {
      color: props.enabled ? "black" : "#ccc",
      backgroundColor: props.open === props.title 
        ? "#e1e1e1" 
        : "white"
    }
    return html`
      <button 
        style=${menuStyle} 
        ref=${this.button} 
        onClick=${() => this.toggleOpen()}
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

class MenuOption extends Component {
  render(props) {
    return html`<div class="option"
      data-selected=${props.selected} 
      onClick=${props.onClick}>
          ${props.children}
    </div>`
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

function MenuBadge(props) {
  return html`<svg width="10" height="10">
    <rect x="1" y="1" rx="2" ry="2" width="8" height="8"
    style="fill:${props.color}" />
  </svg>`
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

  saveFile(data) {
    const filename = prompt("please provide a filename")

    var blob = new Blob([data], {type: 'text/json'}),
    a = document.createElement('a')

    a.download = filename
    a.href = window.URL.createObjectURL(blob)
    a.dataset.downloadurl = ['text/json', a.download, a.href].join(':')
    a.dispatchEvent(new MouseEvent("click"))
  }

  render(props, state) {
    return html`<div id="menubar"
        onMousedown=${ev => this.handleLocalClick(ev)}
      >
      <${Menu} 
        enabled=${props.status === Status.idle}
        open=${state.open}
        title="Files"
        setOpen=${o => this.setOpen(o)}>
        <${MenuOption} onClick=${() => this.saveFile(props.getJSON()[0])}>
            Save Pre Graph
        <//>
        <${MenuOption} onClick=${() => this.saveFile(props.getJSON()[1])}>
            Save Post Graph
        <//>
      <//>
      <${Menu} 
        enabled=${props.status === Status.idle}
        open=${state.open}
        title="View"
        setOpen=${o => this.setOpen(o)}>
        <${MenuOption} 
          onClick=${() => this.setTidiness(Tidiness.untidy)}
          selected=${props.tidiness == Tidiness.untidy}>
            Show All Blocks
        <//>
        <${MenuOption} 
          onClick=${() => this.setTidiness(Tidiness.tidy)}
          selected=${props.tidiness == Tidiness.tidy}>
            Merge Unless Constaints Change
        <//>
        <${MenuOption} 
          onClick=${() => this.setTidiness(Tidiness.veryTidy)}
          selected=${props.tidiness == Tidiness.veryTidy}>
            Merge Unless Branching Occurs
        <//>
        <hr/>
        <${MenuOption} 
            onClick=${props.toggleSyscalls}
            selected=${props.showingSyscalls}>
            <${MenuBadge} color=${Colors.focusedSyscallNode}/> Show Syscalls
        <//>
        <${MenuOption} 
            onClick=${props.toggleSimprocs}
            selected=${props.showingSimprocs}>
            <${MenuBadge} color=${Colors.focusedSimprocNode}/> Show SimProcedure calls
        <//>
        <${MenuOption} 
            onClick=${props.toggleErrors}
            selected=${props.showingErrors}>
            <${MenuBadge} color=${Colors.focusedErrorNode}/> Show Errors
        <//>
        <${MenuOption} 
            onClick=${props.toggleAsserts}
            selected=${props.showingAsserts}>
            <${MenuBadge} color=${Colors.focusedAssertNode}/> Show Asserts
        <//>
      <//>
      <${Menu} 
        enabled=${props.status === Status.idle}
        open=${state.open}
        title="Prune"
        setOpen=${o => this.setOpen(o)}>
        <${MenuOption} onClick=${() => this.prune(noMemoryDiffs)}>
            Completed Branches with Identical Memory
        <//>
        <${MenuOption} onClick=${() => this.prune(noRegisterDiffs)}>
            Completed Branches with Identical Register Contents 
        <//>
        <${MenuOption} onClick=${() => this.prune(noStdDiffs)}>
            Completed Branches with Identical Stdout/Stderr
        <//>
        <${MenuOption} onClick=${() => this.prune(noErrors)}>
            All Completed (Error-free) Branches
        <//>
      <//>
      <${Menu} 
        enabled=${props.status === Status.idle}
        open=${state.open}
        title="Layout"
        setOpen=${o => this.setOpen(o)}>
        <${MenuOption} onClick=${() => this.resetLayout()}>
            Reset
        <//>
      <//>
    </div>`
  }
}
