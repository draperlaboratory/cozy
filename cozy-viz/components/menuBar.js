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
      }).then(({ x, y }) => {
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
  else return noErrors(leaf, other)
}

function noRegisterDiffs(leaf, other) {
  const comparison = leaf.data().compatibilities[other.id()]
  if (Object.keys(comparison.regdiff).length) return false
  else return noErrors(leaf, other)
}

function noErrors(leaf, other) {
  if (leaf.data().error || other.data().error) return false
  else return true
}

function noStdDiffs(leaf, other) {
  if (leaf.data().stdout != other.data().stdout ||
    leaf.data().stderr != other.data().stderr) return false
  else return noErrors(leaf, other)
}

const matchRegex = (regexStr) => (leaf, other) => {
  let regex
  try {
    regex = new RegExp(regexStr)
  } catch (e) {
    if (matchRegex.debounce) return
    matchRegex.debounce = true
    alert("Unreadable Regular Expression")
    setTimeout(() => matchRegex.debounce = false, 500)
  }
  if (!leaf.data().stdout.match(regex)) return false
  if (!other.data().stdout.match(regex)) return false
  else return noErrors(leaf, other)
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
      searchStdoutRegex: ".*",
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
    this.setState({ open })
  }

  handleGlobalClick() {
    if (this.state.open) {
      this.setState({ open: null })
    }
  }

  handleLocalClick(ev) {
    if (this.state.open) {
      ev.stopPropagation()
    }
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

    var blob = new Blob([data], { type: 'text/json' }),
      a = document.createElement('a')

    a.download = filename
    a.href = window.URL.createObjectURL(blob)
    a.dataset.downloadurl = ['text/json', a.download, a.href].join(':')
    a.dispatchEvent(new MouseEvent("click"))
  }

  render(props, state) {
    const enabled = props.status === Status.idle
    return html`<div id="menubar"
        onMousedown=${ev => this.handleLocalClick(ev)}
      >
      <${Menu} 
        enabled=${enabled}
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
        enabled=${enabled}
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
      <${PruneMenu} 
        enabled=${enabled} 
        prune=${props.prune}
        unprune=${props.unprune}
        open=${state.open}
        setOpen=${o => this.setOpen(o)}
      />
      <${Menu} 
        enabled=${enabled}
        open=${state.open}
        title="Layout"
        setOpen=${o => this.setOpen(o)}>
        <${MenuOption} onClick=${() => this.resetLayout()}>
            Reset
        <//>
      <//>
      <${SearchMenu}
        enabled=${enabled}
        open=${state.open}
        setOpen=${o => this.setOpen(o)}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
      />
    </div>`
  }
}

class SearchMenu extends Component {
  constructor() {
    super()
    this.state = {
      searchStdoutRegex: ".*",
    }
  }

  updateSearch(e) {
    this.setState({ searchStdoutRegex: e.target.value }, () => {
      const cyLeft = this.props.cyLeft.cy
      const cyRight = this.props.cyRight.cy
      cyLeft.dim()
      cyRight.dim()
      let regex
      try {
        regex = new RegExp(this.state.searchStdoutRegex)
      } catch (e) {
        return
      }
      const ltargets = cyLeft.nodes()
        .filter(node => node.data().stdout.match(regex))
      const rtargets = cyRight.nodes()
        .filter(node => node.data().stdout.match(regex))
      cyLeft.highlight(ltargets)
      cyRight.highlight(rtargets)
    })
  }

  clearSearch() {
    this.setState({ searchStdoutRegex: '.*' }, () => {
      const cyLeft = this.props.cyLeft.cy
      const cyRight = this.props.cyRight.cy
      cyLeft.dim()
      cyRight.dim()
    })
  }

  render(props, state) {
    return html`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Search"
        setOpen=${o => props.setOpen(o)}>
        <${MenuOption} onClick=${() => props.setOpen(null)}>
          Stdout <input 
            onClick=${e => e.stopPropagation()}
            onInput=${e => this.updateSearch(e)} 
            value=${state.searchStdoutRegex}/>
        <//>
        <${MenuOption} onClick=${() => this.clearSearch(null)}>
          Clear Search 
        <//>
      <//>`
  }
}

class PruneMenu extends Component {
  constructor() {
    super()
    this.state = {
      pruningMemory: false,
      pruningStdout: false,
      pruningRegisters: false,
      pruningCorrect: false,
      pruningDoRegex: false,
      pruningRegex: ".*",
    }
  }

  prune() {
    // I think the user expectation is going to be that with nothing selected,
    // nothing is pruned. But once something is selected, the more pruning
    // requirements we add, the less we prune
    let test = () =>
      this.state.pruningMemory
      || this.state.pruningStdout
      || this.state.pruningRegisters
      || this.state.pruningCorrect
      || this.state.pruningDoRegex

    const extendTest = (f, g) => (l, r) => f(l, r) && g(l, r)

    if (this.state.pruningMemory) test = extendTest(noMemoryDiffs, test)
    if (this.state.pruningStdout) test = extendTest(noStdDiffs, test)
    if (this.state.pruningRegisters) test = extendTest(noRegisterDiffs, test)
    if (this.state.pruningCorrect) test = extendTest(noErrors, test)
    if (this.state.pruningDoRegex) test = extendTest(matchRegex(this.state.pruningRegex), test)

    this.props.prune(test)
    this.props.setOpen(null)

    this.setState({
      pruningMemory: false,
      pruningStdout: false,
      pruningRegisters: false,
      pruningCorrect: false,
      pruningDoRegex: false,
      pruningRegex: ".*"
    })
  }

  render(props, state) { 
    return html`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Prune"
        setOpen=${o => props.setOpen(o)}>
        <${MenuOption} onClick=${() => this.setState({ pruningMemory: !state.pruningMemory })}>
          <input type="checkbox" checked=${state.pruningMemory}/> Identical Memory
        <//>
        <${MenuOption} onClick=${() => this.setState({ pruningRegisters: !state.pruningRegisters })}>
          <input type="checkbox" checked=${state.pruningRegisters}/> Identical Register Contents 
        <//>
        <${MenuOption} onClick=${() => this.setState({ pruningStdout: !state.pruningStdout })}>
          <input type="checkbox" checked=${state.pruningStdout}/> Identical Stdout/Stderr
        <//>
        <${MenuOption} onClick=${() => this.setState({ pruningCorrect: !state.pruningCorrect })}>
          <input type="checkbox" checked=${state.pruningCorrect}/> Error-free
        <//>
        <${MenuOption} onClick=${() => this.setState({ pruningDoRegex: !state.pruningDoRegex })}>
          <input type="checkbox" checked=${state.pruningDoRegex}/> Both Stdout Matching <input 
            onClick=${e => e.stopPropagation()}
            onInput=${e => this.setState({ pruningRegex: e.target.value })} 
            value=${state.pruningRegex}/>
        <//>
        <hr/>
        <${MenuOption} onClick=${() => this.prune()}>
          Prune branches matching all conditions above
        <//>
        <${MenuOption} onClick=${() => { props.unprune(); props.setOpen(null) }}>
          Revert All Pruning
        <//>
      <//>`
  }
}
