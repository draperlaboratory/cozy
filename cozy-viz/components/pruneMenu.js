import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { removeBranch } from '../util/graph-tidy.js';
import Menu from './menu.js'

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

// this test preserves any pair where both sides aren't checked. So it removes
// checked notes, and removes nodes all of whose partners are checked.
function reviewed(leaf, other) {
  if (!leaf.data("checked") && !other.data("checked")) return false
  else return true
}

function equivConstraints(leaf, other) {
  const leftOnlyConcretions = Object.entries(leaf.data().compatibilities).flatMap(
    ([key, compat]) => key == leaf.id() ? [] : compat.conc_args
  )
  const rightOnlyConcretions = Object.entries(other.data().compatibilities).flatMap(
    ([key, compat]) => key == other.id() ? [] : compat.conc_args
  )
  return (rightOnlyConcretions.length + leftOnlyConcretions.length == 0)
}

const matchRegex = (regexStrs) => (leaf, other) => {
  const regexes = []
  try {
    for (const regexStr of regexStrs.split('||')) {
      regexes.push(new RegExp(regexStr))
    }
  } catch (e) {
    if (matchRegex.debounce) return
    matchRegex.debounce = true
    alert("Unreadable Regular Expression")
    setTimeout(() => matchRegex.debounce = false, 500)
  }
  for (const regex of regexes) {
    if (
      leaf.data().stdout.match(regex) &&
      other.data().stdout.match(regex)
    ) { 
      return noErrors(leaf, other) 
    }
  }
  return false
}

export default class PruneMenu extends Component {
  constructor() {
    super()
    this.state = {
      pruningMemory: false,
      pruningStdout: false,
      pruningRegisters: false,
      pruningCorrect: false,
      pruningDoRegex: false,
      pruningChecked: false,
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
    if (this.state.pruningChecked) test = extendTest(reviewed, test)
    if (this.state.pruningDoRegex) test = extendTest(matchRegex(this.state.pruningRegex), test)

    this.prune(test)
  }

  debounceRegex(e) {
    this.setState({ pruningRegex: e.target.value })
    if (this.state.pruningDoRegex) {
      this.setState({ awaitingPrune: true })
      clearTimeout(this.regexDebounceTimeout)
      this.regexDebounceTimeout = setTimeout(() => this.setPrune({ awaitingPrune: null }), 500)
    }
  }

  render(props, state) {
    return html`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Prune"
        setOpen=${o => props.setOpen(o)}>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningMemory: !state.pruningMemory })}>
          <input type="checkbox" checked=${state.pruningMemory}/> Identical Memory
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningRegisters: !state.pruningRegisters })}>
          <input type="checkbox" checked=${state.pruningRegisters}/> Identical Register Contents 
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningStdout: !state.pruningStdout })}>
          <input type="checkbox" checked=${state.pruningStdout}/> Identical Stdout/Stderr
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningCorrect: !state.pruningCorrect })}>
          <input type="checkbox" checked=${state.pruningCorrect}/> Error-free
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningEquivConstraints: !state.pruningEquivConstraints })}>
          <input type="checkbox" checked=${state.pruningEquivConstraints}/> Equivalent Constraints
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningChecked: !state.pruningChecked })}>
          <input type="checkbox" checked=${state.pruningChecked}/> Reviewed
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningDoRegex: !state.pruningDoRegex })}>
          <input type="checkbox" checked=${state.pruningDoRegex}/> Both Stdout Matching <input 
            data-awaiting=${state.awaitingPrune}
            onClick=${e => e.stopPropagation()}
            onInput=${e => this.debounceRegex(e)} 
            value=${state.pruningRegex}/>
        <//>
      <//>`
  }
}
