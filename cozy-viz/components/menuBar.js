import { computePosition } from 'https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm';
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { render } from 'https://unpkg.com/preact@latest?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import { Status, Tidiness } from '../data/cozy-data.js'
import Report from './report.js'
import * as GraphStyle from '../util/graphStyle.js';
import Colors from '../data/colors.js'
import { View } from '../data/cozy-data.js'
import { breadthFirst, cola, cose } from '../data/layouts.js'
import { removeBranch } from '../util/graph-tidy.js';

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

function equivConstraints(leaf,other) {
  const leftOnlyConcretions = Object.entries(leaf.data().compatibilities).flatMap(
    ([key, compat]) => key == leaf.id() ? [] : compat.conc_args
  )
  const rightOnlyConcretions = Object.entries(other.data().compatibilities).flatMap(
    ([key, compat]) => key == other.id() ? [] : compat.conc_args
  )
  return (rightOnlyConcretions.length + leftOnlyConcretions.length == 0)
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

  resetLayout(layout, view) {
    this.props.resetLayout(layout, view)
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

  openReport() {
    this.reportWindow = open()
    if (!this.reportWindow) {
      alert("couldn't open report - double check that cozy has permission to open new windows in your popup-blocker")
    }
    render(html`<${Report} window=${this.reportWindow}/>`, this.reportWindow.document.body)
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
        <${MenuOption} onClick=${() => this.saveFile(props.getJSON())}>
          Save Graph
        <//>
        <${MenuOption} onClick=${() => this.openReport()}>
          Open New Report
        <//>
      <//>
      <${ViewMenu}
        ref=${props.viewMenu}
        enabled=${enabled && props.view == View.plain} 
        tidiness=${props.tidiness}
        pruneMenu=${props.pruneMenu}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
        open=${state.open}
        regenerateFocus=${props.regenerateFocus}
        refreshLayout=${props.refreshLayout}
        batch=${props.batch}
        setOpen=${o => this.setOpen(o)}
      />
      <${PruneMenu} 
        ref=${props.pruneMenu}
        enabled=${enabled && props.view == View.plain} 
        viewMenu=${props.viewMenu}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
        refreshLayout=${props.refreshLayout}
        open=${state.open}
        setOpen=${o => this.setOpen(o)}
      />
      <${Menu} 
        enabled=${enabled}
        open=${state.open}
        title="Layout"
        setOpen=${o => this.setOpen(o)}>
        <${MenuOption} 
          onClick=${() => this.resetLayout(breadthFirst, View.plain)}
          selected=${props.layout.name == "breadthfirst" && props.view == View.plain}>
            Tree
        <//>
        <${MenuOption} 
          onClick=${() => this.resetLayout(breadthFirst, View.cfg)}
          selected=${props.layout.name == "breadthfirst" && props.view == View.cfg}>
            CFG - Tree layout
        <//>
        <${MenuOption} onClick=${() => this.resetLayout()}
          onClick=${() => this.resetLayout(cose, View.cfg)}
          selected=${props.layout.name == "cose" && props.view == View.cfg}>
            CFG - Cose layout
        <//>
        <${MenuOption} 
          onClick=${() => this.resetLayout(cola, View.cfg)}
          selected=${props.layout.name == "cola" && props.view == View.cfg}>
            CFG - Cola layout
        <//>
        <${MenuOption} onClick=${() => this.resetLayout()}>
            Refresh
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
      searchStdoutRegex: "",
    }
  }

  updateSearch(e) {
    if (e.target.value == '') this.clearSearch()
    else {
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
  }

  clearSearch() {
    this.setState({ searchStdoutRegex: '' }, () => {
      const cyLeft = this.props.cyLeft.cy
      const cyRight = this.props.cyRight.cy
      cyLeft.dim()
      cyRight.dim()
    })
    this.props.setOpen(null)
  }

  render(props, state) {
    return html`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Search"
        setOpen=${o => props.setOpen(o)}>
        <${MenuOption} onClick=${() => props.setOpen(null)}>
          Stdout <input 
            placeholder=".*"
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
      pruningEquivConstraints: false,
      pruningRegex: ".*",
      awaitingPrune: null,
    }
    this.prune.bind(this)
  }
  
  // prune all branches whose compatibilities all fail some test (e.g. all have
  // the same memory contents as the given branch)
  prune(test) {
    const leaves1 = this.props.cyLeft.cy.nodes().leaves()
    const leaves2 = this.props.cyRight.cy.nodes().leaves()
    for (const leaf of [...leaves1, ...leaves2]) {
      let flag = true
      let other = leaf.cy() == this.props.cyLeft.cy ? this.props.cyRight.cy : this.props.cyLeft.cy
      for (const key in leaf.data().compatibilities) {
        const otherleaf = other.nodes(`#${key}`)
        if (otherleaf.length == 0) continue
        flag &&= test(leaf, otherleaf)
      }
      if (flag) removeBranch(leaf)
    }
    this.props.cyLeft.cy.refocus()
    this.props.cyRight.cy.refocus()
  }

  setPrune(update) {
    this.setState(update, () => {
      // we retidy before we set a pruning level to get a clean slate, in case
      // we're actually removing some pruning
      this.props.viewMenu.current.retidy()
      this.props.refreshLayout()
      this.doPrune()
    })
  }

  doPrune() {
    // true means "prune"
    let test = () => false

    // So the more tests are added disjunctively, the more branches will be pruned
    const extendTest = (f, g) => (l, r) => f(l, r) || g(l, r)

    if (this.state.pruningMemory) test = extendTest(noMemoryDiffs, test)
    if (this.state.pruningStdout) test = extendTest(noStdDiffs, test)
    if (this.state.pruningEquivConstraints) test = extendTest(equivConstraints, test)
    if (this.state.pruningRegisters) test = extendTest(noRegisterDiffs, test)
    if (this.state.pruningCorrect) test = extendTest(noErrors, test)
    if (this.state.pruningDoRegex) test = extendTest(matchRegex(this.state.pruningRegex), test)

    this.prune(test)
  }

  debounceRegex(e) {
    this.setState({ pruningRegex: e.target.value })
    if (this.state.pruningDoRegex) {
      this.setState({ awaitingPrune: true })
      clearTimeout(this.regexDebounceTimeout)
      this.regexDebounceTimeout = setTimeout(() => this.setPrune({ awaitingPrune: null }), 1000)
    }
  }

  render(props, state) { 
    return html`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Prune"
        setOpen=${o => props.setOpen(o)}>
        <${MenuOption} onClick=${() => this.setPrune({ pruningMemory: !state.pruningMemory })}>
          <input type="checkbox" checked=${state.pruningMemory}/> Identical Memory
        <//>
        <${MenuOption} onClick=${() => this.setPrune({ pruningRegisters: !state.pruningRegisters })}>
          <input type="checkbox" checked=${state.pruningRegisters}/> Identical Register Contents 
        <//>
        <${MenuOption} onClick=${() => this.setPrune({ pruningStdout: !state.pruningStdout })}>
          <input type="checkbox" checked=${state.pruningStdout}/> Identical Stdout/Stderr
        <//>
        <${MenuOption} onClick=${() => this.setPrune({ pruningCorrect: !state.pruningCorrect })}>
          <input type="checkbox" checked=${state.pruningCorrect}/> Error-free
        <//>
        <${MenuOption} onClick=${() => this.setPrune({ pruningEquivConstraints: !state.pruningEquivConstraints })}>
          <input type="checkbox" checked=${state.pruningEquivConstraints}/> Equivalent Constraints
        <//>
        <${MenuOption} onClick=${() => this.setPrune({ pruningDoRegex: !state.pruningDoRegex })}>
          <input type="checkbox" checked=${state.pruningDoRegex}/> Both Stdout Matching <input 
            data-awaiting=${state.awaitingPrune}
            onClick=${e => e.stopPropagation()}
            onInput=${e => this.debounceRegex(e)} 
            value=${state.pruningRegex}/>
        <//>
      <//>`
  }
}

class ViewMenu extends Component {
  constructor() {
    super()
    this.state = {
      showingSyscalls: true, // we start with syscalls visible
      showingSimprocs: true, // we start with SimProcedure calls visible
      showingErrors: true, // we start with errors visible
      showingAsserts: true, // we start with asserts visible
      showingPostconditions: true, // we start with postconditions visible
      tidiness: Tidiness.untidy, // we're not yet tidying anything
    }
    this.toggleErrors = this.toggleErrors.bind(this)
    this.togglePostconditions = this.togglePostconditions.bind(this)
    this.toggleView = this.toggleView.bind(this)
    this.toggleSyscalls = this.toggleSyscalls.bind(this)
    this.toggleSimprocs = this.toggleSimprocs.bind(this)
    this.toggleAsserts = this.toggleAsserts.bind(this)
  }

  componentDidUpdate(prevProps, prevState) {
    if (prevState.tidiness !== this.state.tidiness) {
      // when we actually change tidiness, we need to clean up the layout
      // afterwards and reapply any pruning
      this.props.pruneMenu.current.doPrune()
      this.props.refreshLayout()
    }
  }

  retidy() {
    this.setTidiness(this.state.tidiness)
  }

  setTidiness(tidiness) {
    this.props.batch(() => {
      this.props.cyLeft.cy.json({ elements: JSON.parse(this.props.cyLeft.orig).elements })
      this.props.cyRight.cy.json({ elements: JSON.parse(this.props.cyRight.orig).elements })
      // refocus all foci, and reset viewport
      this.props.cyLeft.cy.nodes().map(node => node.ungrabify())
      this.props.cyRight.cy.nodes().map(node => node.ungrabify())

      switch (tidiness) {
        case Tidiness.untidy: break;
        case Tidiness.tidy: this.tidy({}); break;
        case Tidiness.veryTidy: this.tidy({ mergeConstraints: true }); break;
      }
      this.setState({ tidiness }, this.props.regenerateFocus)
    })
  }

  tidy(opts) {
    // merge similar nodes
    this.props.cyLeft.cy.tidy(opts)
    this.props.cyRight.cy.tidy(opts)
    // remove all foci, and reset viewport
    this.props.cyLeft.cy.refocus().fit()
    this.props.cyRight.cy.refocus().fit()
  }

  toggleView(type) {
    this.setState(oldState => {
      GraphStyle.settings[type] = !oldState[type];
      this.props.cyLeft.cy.style().update()
      this.props.cyRight.cy.style().update()
      return { 
        [type]: !oldState[type]
      }
    })
  }

  toggleSyscalls() { this.toggleView("showingSyscalls") }

  toggleSimprocs() { this.toggleView("showingSimprocs") }

  toggleErrors() { this.toggleView("showingErrors") }

  toggleAsserts() { this.toggleView("showingAsserts") }

  togglePostconditions() { this.toggleView("showingPostconditions") }

  render (props, state) {
      return html`<${Menu}
        enabled=${props.enabled}
        open=${props.open}
        title="View"
        setOpen=${o => props.setOpen(o)}>
        <${MenuOption} 
          onClick=${() => state.tidiness !== Tidiness.untidy && this.setTidiness(Tidiness.untidy)}
          selected=${state.tidiness == Tidiness.untidy}>
            Show All Blocks
        <//>
        <${MenuOption} 
          onClick=${() => state.tidiness !== Tidiness.tidy && this.setTidiness(Tidiness.tidy)}
          selected=${state.tidiness == Tidiness.tidy}>
            Merge Unless Constaints Change
        <//>
        <${MenuOption} 
          onClick=${() => state.tidiness !== Tidiness.veryTidy && this.setTidiness(Tidiness.veryTidy)}
          selected=${state.tidiness == Tidiness.veryTidy}>
            Merge Unless Branching Occurs
        <//>
        <hr/>
        <${MenuOption} 
          onClick=${this.toggleSyscalls}
          selected=${state.showingSyscalls}>
            <${MenuBadge} color=${Colors.focusedSyscallNode}/> Show Syscalls
        <//>
        <${MenuOption} 
          onClick=${this.toggleSimprocs}
          selected=${state.showingSimprocs}>
            <${MenuBadge} color=${Colors.focusedSimprocNode}/> Show SimProcedure calls
        <//>
        <${MenuOption} 
          onClick=${this.toggleErrors}
          selected=${state.showingErrors}>
            <${MenuBadge} color=${Colors.focusedErrorNode}/> Show Errors
        <//>
        <${MenuOption} 
          onClick=${this.toggleAsserts}
          selected=${state.showingAsserts}>
            <${MenuBadge} color=${Colors.focusedAssertNode}/> Show Asserts
        <//>
        <${MenuOption} 
          onClick=${this.togglePostconditions}
          selected=${state.showingPostconditions}>
            <${MenuBadge} color=${Colors.focusedPostconditionNode}/> Show Postcondition failures
        <//>
      <//>`
  }
}
