import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'

import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import cytoscape from "https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm"
import Tooltip from './tooltip.js';
import DiffPanel from './diffPanel.js';
import MenuBar from './menuBar.js';
import { focusMixin } from '../util/focusMixin.js';
import { segmentationMixin } from '../util/segmentationMixin.js';
import * as GraphStyle from '../util/graphStyle.js';
import { tidyGraph, removeBranch } from '../util/graph-tidy.js';
import { Status, Tidiness } from '../data/cozy-data.js'

const standardLayout = {
  name: 'breadthfirst',
  directed: true,
  spacingFactor: 2
}

export default class App extends Component {

  constructor() {
    super();
    this.state = {
      status: Status.unloaded, // awaiting graph data
      tidiness: Tidiness.untidy, // we're not yet tidying anything
      showingSyscalls: true, // we start with syscalls visible
      showingSimprocs: true, // we start with SimProcedure calls visible
      showingErrors: true, // we start with errors visible
      showingAsserts: true, // we start with asserts visible
    }
    this.cy1 = createRef()
    this.cy2 = createRef()
    this.cy1.other = this.cy2
    this.cy2.other = this.cy1
    this.tooltip = createRef()

    this.prune = this.prune.bind(this)
    this.unprune = this.unprune.bind(this)
    this.handleDragleave = this.handleDragleave.bind(this)
    this.handleDragover = this.handleDragover.bind(this)
    this.clearTooltip = this.clearTooltip.bind(this)
    this.resetLayout = this.resetLayout.bind(this)
    this.toggleErrors = this.toggleErrors.bind(this)
    this.toggleView = this.toggleView.bind(this)
    this.toggleSyscalls = this.toggleSyscalls.bind(this)
    this.toggleSimprocs = this.toggleSimprocs.bind(this)
    this.toggleAsserts = this.toggleAsserts.bind(this)
    this.getJSON = this.getJSON.bind(this)

    window.app = this
  }

  componentDidMount() {
    const urlParams = new URLSearchParams(window.location.search);
    const isServedPre = urlParams.get('pre')
    const isServedPost = urlParams.get('post')
    if (isServedPre) {
      fetch(isServedPre)
        .then(rslt => rslt.json())
        .then(raw => {
          const obj = JSON.parse(raw)
          if (!obj.elements) throw new Error("Malformed post-patch JSON")
          this.mountToCytoscape(obj, this.cy1)
        })
        .catch(e => console.error(e))
    }
    if (isServedPost) {
      fetch(isServedPost)
        .then(rslt => rslt.json())
        .then(raw => {
          const obj = JSON.parse(raw)
          if (!obj.elements) throw new Error("Malformed post-patch JSON")
          this.mountToCytoscape(obj, this.cy2)
        })
        .catch(e => console.error(e))

    }
  }

  handleClick(ev) {

    //bail out if graphs are not available
    if (this.state.status == Status.unloaded) {
      alert("Please load both graphs before attempting comparison.")
      return
    }

    const isLeft = ev.target.cy() == this.cy1.cy
    const self = ev.cy
    const other = ev.cy.ref.other.cy
    // we're selecting just a segment if the shift key is held
    const segmentSelect = ev.originalEvent.shiftKey
    // we're refining if we click on an existing locus, there's more than
    // one such, and we're not switching from a shift to regular click
    const refining = 
      self.loci?.includes(ev.target) && 
      self.loci.length > 1 &&
      segmentSelect == this.lastSegmentSelect

    this.lastSegmentSelect = segmentSelect
    
    // ranges are connected sets of nodes, not necessarily linear
    let selfRange

    // segments are linear sequences of nodes given by a top and bottom
    let selfSegment

    if (segmentSelect) {
      // if we're selecting a segment, choose the corresponding segment
      selfRange = self.getRangeOf(ev.target)
      selfSegment = self.rangeToSegment(selfRange)
      self.blur().focusRange(selfRange)
    } else {
      // otherwise, bail out if we're not on a leaf
      if (ev.target.outgoers().length !== 0) return
      // and choose the full branch, if we are on a leaf
      const selfRoot = ev.cy.nodes().roots()[0]
      selfSegment = { top: selfRoot, bot: ev.target }
      selfRange = self.segmentToRange(selfSegment)
      self.blur().focus(ev.target)
    }

    // unconditionally focus the clicked segment
    if (isLeft) this.setState({leftFocus: selfSegment})
    else this.setState({rightFocus: selfSegment})

    // if we're not refining, we need to update the focus on the other side
    if (!refining) {
      let otherSegment
      if (segmentSelect) {
        const compats = self.getLeavesCompatibleWith(ev.target, other)
        // if we're selecting a segment, get the compatible range and focus it
        const otherRange = other.getCompatibilityRangeOf(self.getMinimalCeiling(compats), self)
        other.blur().focusRange(otherRange)
        if (other.loci.length == 1) {
          //if there's only one compatibility, introduce a segment
          otherSegment = other.rangeToSegment(otherRange)
        }
      } else {
        // if we're selecting a full branch, get compatible roots and focus those
        const compatibilities = ev.target.data().compatibilities
        other
          .blur()
          .focus(other.nodes().filter(node => +node.data().id in compatibilities))
        if (other.loci.length == 1) {
          // if there's only one compatibility, start a diff
          const otherRoot = other.nodes().roots()[0]
          otherSegment = { top: otherRoot, bot: other.loci[0] }
        }
      }

      if (otherSegment) {
        // if we picked out a corresponding segment, focus it.
          if (isLeft) this.setState({rightFocus: otherSegment})
        else this.setState({leftFocus: otherSegment})
      } else {
        //otherwise clear the focus
        if (isLeft) this.setState({rightFocus: null, leftFocus: selfSegment})
        else this.setState({leftFocus:null, rightFocus:selfSegment})
      }
    }
  }

  refresh() {
    this.cy1.cy.json({ elements: JSON.parse(this.cy1.orig).elements })
    this.cy2.cy.json({ elements: JSON.parse(this.cy2.orig).elements })
    // refocus all foci, and reset viewport
    this.cy1.cy.refocus().fit()
    this.cy2.cy.refocus().fit()
    this.setState({ status: Status.idle })
  }

  getJSON() {
    return [this.cy1.orig, this.cy2.orig]
  }

  tidy(opts) {
    // merge similar nodes
    tidyGraph(this.cy1.cy, opts)
    tidyGraph(this.cy2.cy, opts)
    // reset layout and viewport
    this.cy1.cy.layout(standardLayout).run()
    this.cy2.cy.layout(standardLayout).run()
    // remove all foci, and reset viewport
    this.cy1.cy.refocus().fit()
    this.cy2.cy.refocus().fit()
    this.setState({ 
      status: Status.idle,
      leftFocus: this.state.leftFocus ? {... this.state.leftFocus} : null,
      rightFocus: this.state.rightFocus ? {... this.state.rightFocus} : null,
      // we regenerate the focus, 
      // so that the assembly diff is regenerated, 
      // so that its lines are properly mapped on to the merged nodes,
    })
  }

  toggleView(type) {
    this.setState(oldState => {
      GraphStyle.settings[type] = !oldState[type];
      this.cy1.cy.style().update()
      this.cy2.cy.style().update()
      return { 
        [type]: !oldState[type]
      }
    })
  }

  toggleSyscalls() { this.toggleView("showingSyscalls") }

  toggleSimprocs() { this.toggleView("showingSimprocs") }

  toggleErrors() { this.toggleView("showingErrors") }

  toggleAsserts() { this.toggleView("showingAsserts") }

  async handleDrop(ev, ref) {
    ev.stopPropagation()
    ev.preventDefault()
    ev.target.classList.remove("dragHover")
    const file = ev.dataTransfer.files[0]
    const raw = await file.text().then(text => JSON.parse(text))
    this.mountToCytoscape(raw, ref)
  }

  handleDragover(ev) {
    ev.stopPropagation()
    ev.preventDefault()
    ev.target.classList.add("dragHover")
  }

  handleDragleave(ev) {
    ev.stopPropagation()
    ev.preventDefault()
    ev.target.classList.remove("dragHover")
  }

  mountToCytoscape(raw, ref) {
    if (ref.cy) ref.cy.destroy()
    const cy = cytoscape({
      style: GraphStyle.style,
      elements: raw.elements
    })

    // mount to DOM
    cy.mount(ref.current)

    // monkeypatch in additional methods
    Object.assign(cy, focusMixin);
    Object.assign(cy, segmentationMixin);
    cy.debugData = cy.nodes().roots()[0].data("debug")

    // set layout
    cy.layout(standardLayout).run()

    cy.on('add', ev => {
      if (ev.target.group() === 'nodes') {
        this.initializeNode(ev.target)
      }
    })

    // clear focus on click without target
    cy.on('click', ev => {
      if (!ev.target.group) {
        this.batch(() => {
          this.cy1.cy?.blur()
          this.cy2.cy?.blur()
          this.setState({leftFocus: null, rightFocus: null})
          this.tooltip.current.clearTooltip()
        })
      }
    })

    // stow graph data in reference
    ref.cy = cy
    ref.orig = JSON.stringify(cy.json())

    // stow reference data in graph
    cy.ref = ref

    cy.nodes().map(node => this.initializeNode(node))

    this.setState({
      status: !this.cy1.cy || !this.cy2.cy
        ? Status.unloaded
        : Status.idle
    })
  }

  initializeNode(node) {

    // turn off manual graph dragging
    node.ungrabify()

    // add methods for actively querying display features

    // mouseover handling
    node.on('mouseout', ev => {
      ev.cy.container().style.cursor = "default"
    })

    node.on('mouseover', ev => {


      if (ev.target.outgoers().length == 0) {
        ev.cy.container().style.cursor = "pointer"
      }

      if (ev.cy.loci && !(ev.target.hasClass('pathHighlight') || ev.target.hasClass('availablePath'))) return;
      this.tooltip.current.attachTo(ev.target)
    })

    node.on('click', ev => this.handleClick(ev))
  }

  startRender(method) {
    this.setState({ status: Status.rendering }, method)
  }

  batch(cb) {
    this.cy1.cy?.startBatch()
    this.cy2.cy?.startBatch()
    cb()
    this.cy1.cy?.endBatch()
    this.cy2.cy?.endBatch()
  }

  async setTidiness(tidiness) {
    // we insert a few milliseconds delay to allow for prior state updates to
    // render
    await new Promise(r => setTimeout(r, 50))
    switch (tidiness) {
      case Tidiness.untidy: {
        this.refresh()
        break;
      }
      case Tidiness.tidy: {
        // technically we could hold off on the refresh here unless we're
        // already veryTidy, but that's probably a premature optimization
        this.batch(() => {
          this.refresh()
          this.tidy({})
        })
        break;
      }
      case Tidiness.veryTidy: {
        this.batch(() => {
          this.refresh()
          this.tidy({ mergeConstraints: true })
        })
        break;
      }
    }
    this.setState({ tidiness, status: Status.idle })
  }

  resetLayout() {
    this.batch(() => {
      this.cy1.cy.layout(standardLayout).run()
      this.cy2.cy.layout(standardLayout).run()
    })
  }

  clearTooltip() {
    this.tooltip.current.clearTooltip()
  }

  // prune all branches whose compatibilities all fail some test (e.g. all have
  // the same memory contents as the given branch)
  prune(test) {
    const leaves1 = this.cy1.cy.nodes().leaves()
    const leaves2 = this.cy2.cy.nodes().leaves()
    for (const leaf of [...leaves1, ...leaves2]) {
      let flag = true
      let other = leaf.cy() == this.cy1.cy ? this.cy2.cy : this.cy1.cy
      for (const key in leaf.data().compatibilities) {
        const otherleaf = other.nodes(`#${key}`)
        if (otherleaf.length == 0) continue
        flag &&= test(leaf, otherleaf)
      }
      if (flag) removeBranch(leaf)
    }
    this.cy1.cy.refocus()
    this.cy2.cy.refocus()
  }

  unprune() {
    this.setTidiness(this.state.tidiness)
  }

  render(_props, state) {
    // TODO I could get rid of a lot of lambdas here if I properly bound "this"
    // in some of these methods
    return html`
      <${Tooltip} ref=${this.tooltip}/>
      <${MenuBar} 
        setTidiness=${level => this.startRender(() => this.setTidiness(level))}
        cyLeft=${this.cy1}
        cyRight=${this.cy2}
        prune=${this.prune}
        unprune=${this.unprune}
        resetLayout=${this.resetLayout}
        tidiness=${state.tidiness}
        status=${state.status}
        showingSyscalls=${state.showingSyscalls}
        showingSimprocs=${state.showingSimprocs}
        showingErrors=${state.showingErrors}
        showingAsserts=${state.showingAsserts}
        toggleSyscalls=${this.toggleSyscalls}
        toggleSimprocs=${this.toggleSimprocs}
        toggleErrors=${this.toggleErrors}
        toggleAsserts=${this.toggleAsserts}
        getJSON=${this.getJSON}
      />
      <div id="main-view">
        <span id="labelLeft">prepatch</span>
        <span id="labelRight">postpatch</span>
        <div 
          onMouseEnter=${this.clearTooltip} 
          onDragover=${this.handleDragover}
          onDragleave=${this.handleDragleave}
          onDrop=${ev => this.startRender(() => this.handleDrop(ev, this.cy1))} 
          ref=${this.cy1} id="cy1">
        </div>
        <div 
          onMouseEnter=${this.clearTooltip} 
          onDragover=${this.handleDragover}
          onDragleave=${this.handleDragleave}
          onDrop=${ev => this.startRender(() => this.handleDrop(ev, this.cy2))}
          ref=${this.cy2} id="cy2">
        </div>
      </div>
      <${DiffPanel} 
        rightFocus=${state.rightFocus}
        leftFocus=${state.leftFocus}
        onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
      />
      ${state.status == Status.rendering && html`<span id="status-indicator">rendering...</span>`}
    `
  }
}
