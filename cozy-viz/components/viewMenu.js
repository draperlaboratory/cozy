import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Tidiness } from '../data/cozy-data.js'
import { Component } from 'https://unpkg.com/preact@latest?module'
import * as GraphStyle from '../util/graphStyle.js';
import Menu from './menu.js'
import Colors from '../data/colors.js'

function MenuBadge(props) {
  return html`<svg width="10" height="10">
    <rect x="1" y="1" rx="2" ry="2" width="8" height="8"
    style="fill:${props.color}" />
  </svg>`
}

export default class ViewMenu extends Component {
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

  componentDidUpdate(_prevProps, prevState) {
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
      // restore any checked nodes
      this.props.cyLeft.cy.restoreCheckMarks()

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

  render(props, state) {
    return html`<${Menu}
        enabled=${props.enabled}
        open=${props.open}
        title="View"
        setOpen=${o => props.setOpen(o)}>
        <${Menu.Option} 
          onClick=${() => state.tidiness !== Tidiness.untidy && this.setTidiness(Tidiness.untidy)}
          selected=${state.tidiness == Tidiness.untidy}>
            Show All Blocks
        <//>
        <${Menu.Option} 
          onClick=${() => state.tidiness !== Tidiness.tidy && this.setTidiness(Tidiness.tidy)}
          selected=${state.tidiness == Tidiness.tidy}>
            Merge Unless Constaints Change
        <//>
        <${Menu.Option} 
          onClick=${() => state.tidiness !== Tidiness.veryTidy && this.setTidiness(Tidiness.veryTidy)}
          selected=${state.tidiness == Tidiness.veryTidy}>
            Merge Unless Branching Occurs
        <//>
        <hr/>
        <${Menu.Option} 
          onClick=${this.toggleSyscalls}
          selected=${state.showingSyscalls}>
            <${MenuBadge} color=${Colors.focusedSyscallNode}/> Show Syscalls
        <//>
        <${Menu.Option} 
          onClick=${this.toggleSimprocs}
          selected=${state.showingSimprocs}>
            <${MenuBadge} color=${Colors.focusedSimprocNode}/> Show SimProcedure calls
        <//>
        <${Menu.Option} 
          onClick=${this.toggleErrors}
          selected=${state.showingErrors}>
            <${MenuBadge} color=${Colors.focusedErrorNode}/> Show Errors
        <//>
        <${Menu.Option} 
          onClick=${this.toggleAsserts}
          selected=${state.showingAsserts}>
            <${MenuBadge} color=${Colors.focusedAssertNode}/> Show Asserts
        <//>
        <${Menu.Option} 
          onClick=${this.togglePostconditions}
          selected=${state.showingPostconditions}>
            <${MenuBadge} color=${Colors.focusedPostconditionNode}/> Show Postcondition failures
        <//>
      <//>`
  }
}
