import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'

import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import cytoscape from "https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm"
import cytoscapeCola from 'https://cdn.jsdelivr.net/npm/cytoscape-cola@2.5.1/+esm'
import Tooltip from './tooltip.js';
import DiffPanel from './diffPanel.js';
import MenuBar from './menuBar.js';
import { focusMixin } from '../util/focusMixin.js';
import { segmentationMixin } from '../util/segmentationMixin.js';
import * as GraphStyle from '../util/graphStyle.js';
import { tidyMixin, removeBranch } from '../util/graph-tidy.js';
import { Status, Tidiness, View } from '../data/cozy-data.js'
import { breadthFirst } from '../data/layouts.js'

cytoscape.use(cytoscapeCola)

export default class App extends Component {

  constructor() {
    super();
    this.state = {
      status: Status.unloaded, // awaiting graph data
      tidiness: Tidiness.untidy, // we're not yet tidying anything
      layout: breadthFirst, // we start with the breadthfirst layout
      view: View.plain, //we start with all nodes visible, not a CFG
      prelabel : "prepatch",
      postlabel : "postpatch"
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
    if (this.state.view == View.plain) this.handlePlainClick(ev)
    if (this.state.view == View.cfg) this.handleCFGClick(ev)
  }

  handleCFGClick(ev) {
    if (!ev.originalEvent.shiftKey) return
    const addr = ev.target.data('address')
    this.resetLayout(breadthFirst, View.plain)
    const similar = ev.target.cy().nodes(`[address=${addr}]`)
    ev.target.cy().highlight(similar)
  }

  handlePlainClick(ev) {

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
    this.cy1.cy.nodes().map(node => node.ungrabify())
    this.cy2.cy.nodes().map(node => node.ungrabify())
    this.cy1.cy.refocus().fit()
    this.cy2.cy.refocus().fit()
    this.setState({ status: Status.idle })
  }

  getJSON() {
    return JSON.stringify({
      pre : {
        data: JSON.parse(this.cy1.orig),
        name: this.state.prelabel
      }, 
      post : {
        data : JSON.parse(this.cy2.orig),
        name: this.state.postlabel
      }
    })
  }

  tidy(opts) {
    // merge similar nodes
    this.cy1.cy.tidy(opts)
    this.cy2.cy.tidy(opts)
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


  async handleDrop(ev) {
    ev.stopPropagation()
    ev.preventDefault()
    ev.currentTarget.classList.remove("dragHover")
    const file = ev.dataTransfer.files[0]
    const raw = await file.text().then(JSON.parse)
    this.setState({
      prelabel: raw.pre.name,
      postlabel: raw.post.name,
    })
    this.mountToCytoscape(raw.pre.data, this.cy1)
    this.mountToCytoscape(raw.post.data, this.cy2)
  }

  handleDragover(ev) {
    console.log(ev)
    ev.stopPropagation()
    ev.preventDefault()
    ev.currentTarget.classList.add("dragHover")
  }

  handleDragleave(ev) {
    ev.stopPropagation()
    ev.preventDefault()
    ev.currentTarget.classList.remove("dragHover")
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
    Object.assign(cy, tidyMixin);
    Object.assign(cy, segmentationMixin);
    cy.debugData = cy.nodes().roots()[0].data("debug")

    // set layout
    ref.currentLayout = cy.layout(this.state.layout).run()

    cy.on('add', ev => {
      if (ev.target.group() === 'nodes') {
        this.initializeNode(ev.target)
      }
    })

    // clear focus on click without target
    cy.on('click', ev => {
      if (this.state.view == View.cfg) return
      if (!ev.target.group) {
        this.batch(() => {
          this.cy1.cy?.blur()
          this.cy2.cy?.blur()
          this.setState({leftFocus: null, rightFocus: null})
          this.tooltip.current.clearTooltip()
        })
      }
    })

    cy.on('zoom pan',() => {
      this.tooltip.current.clearTooltip()
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

  setTidiness(tidiness) {
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

  resetLayout(layout, view) {
    this.setState(oldState => {
      layout = layout ?? oldState.layout
      if (view != oldState.view) {
        if (view == View.cfg) {
          // we're going from View.plain to View.cfg
          this.cy1.cy.mergeByAddress()
          this.cy2.cy.mergeByAddress()
        } else if (view == View.plain) {
          //we're going from View.cfg to View.plain
          this.cy1.cy.removeCFGData()
          this.cy2.cy.removeCFGData()
          this.setTidiness(this.state.tidiness)
        } else {
          //no view given, we're just recomputing the view,
          view = oldState.view
        }
      }
      this.updateLayout(layout)

      return {view, layout}
    })
  }

  updateLayout(layout) {
    layout = layout || this.state.layout
    this.cy1.currentLayout.stop()
    this.cy2.currentLayout.stop()
    this.cy1.currentLayout = this.cy1.cy.layout(layout).run()
    this.cy2.currentLayout = this.cy2.cy.layout(layout).run()
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
    this.updateLayout()
  }

  render(_props, state) {
    // TODO I could get rid of a lot of lambdas here if I properly bound "this"
    // in some of these methods
    return html`
      <${Tooltip} ref=${this.tooltip}/>
      <${MenuBar} 
        setTidiness=${level => this.startRender(() => {
          this.setTidiness(level); this.updateLayout()
        })}
        cyLeft=${this.cy1}
        cyRight=${this.cy2}
        prune=${this.prune}
        unprune=${this.unprune}
        view=${state.view}
        layout=${state.layout}
        resetLayout=${this.resetLayout}
        tidiness=${state.tidiness}
        status=${state.status}
        showingSyscalls=${state.showingSyscalls}
        showingSimprocs=${state.showingSimprocs}
        showingErrors=${state.showingErrors}
        showingAsserts=${state.showingAsserts}
        showingPostconditions=${state.showingPostconditions}
        toggleSyscalls=${this.toggleSyscalls}
        toggleSimprocs=${this.toggleSimprocs}
        toggleErrors=${this.toggleErrors}
        togglePostconditions=${this.togglePostconditions}
        toggleAsserts=${this.toggleAsserts}
        getJSON=${this.getJSON}
      />
      <div id="main-view"
        onDragover=${this.handleDragover}
        onDragleave=${this.handleDragleave}
        onDrop=${ev => this.startRender(() => this.handleDrop(ev))} 
      >
        <span id="labelLeft">${state.prelabel}</span>
        <span id="labelRight">${state.postlabel}</span>
        <div 
          onMouseEnter=${this.clearTooltip} 
          ref=${this.cy1}
           id="cy1">
        </div>
        <div 
          onMouseEnter=${this.clearTooltip} 
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
