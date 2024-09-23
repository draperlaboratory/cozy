import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'

import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import cytoscape from "https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm"
import cytoscapeCola from 'https://cdn.jsdelivr.net/npm/cytoscape-cola@2.5.1/+esm'
import Tooltip from './tooltip.js';
import DiffPanel from './diffPanel.js';
import MenuBar from './menuBar.js';
import { focusMixin } from '../util/focusMixin.js';
import { checkedMixin } from '../util/checkedMixin.js';
import { Segment } from '../util/segmentation.js';
import { segmentationMixin } from '../util/segmentationMixin.js';
import * as GraphStyle from '../util/graphStyle.js';
import { tidyMixin } from '../util/graph-tidy.js';
import { Status, View } from '../data/cozy-data.js'
import { breadthFirst } from '../data/layouts.js'

cytoscape.use(cytoscapeCola)

export default class App extends Component {

  constructor() {
    super();
    this.state = {
      status: Status.unloaded, // awaiting graph data
      layout: breadthFirst, // we start with the breadthfirst layout
      view: View.plain, //we start with all nodes visible, not a CFG
      prelabel: "prepatch",
      postlabel: "postpatch",
    }
    this.cy1 = createRef()
    this.cy2 = createRef()
    this.cy1.other = this.cy2
    this.cy2.other = this.cy1
    this.tooltip = createRef()

    this.handleDragleave = this.handleDragleave.bind(this)
    this.handleDragover = this.handleDragover.bind(this)
    this.clearTooltip = this.clearTooltip.bind(this)
    this.resetLayout = this.resetLayout.bind(this)
    this.getJSON = this.getJSON.bind(this)

    this.viewMenu = createRef()
    this.pruneMenu = createRef()

    window.app = this
  }

  // Produces an object encapsulating data and methods needed by a cozy report
  // window.
  getReportInterface() {
    return {
      prelabel: this.state.prelabel,
      postlabel: this.state.postlabel,
      pruningStatus: this.pruneMenu.current.state,
      leftPanelRef: this.cy1,
      refreshPrune: () => {
        //we might need to refresh the pruning of the tree, if we've
        //checked/unchecked a new report item and the tree is pruning checked
        //branches
        if (this.pruneMenu.current.state.pruningChecked) {
          this.pruneMenu.current.setPrune({})
        }
      },
      focusLeafById: (id) => {
        const leaf = this.cy1.cy.nodes(`#${id}`)
        const selfCy = this.cy1.cy
        const otherCy = this.cy2.cy
        const selfRoot = selfCy.nodes().roots()[0]
        const selfSegment = new Segment(selfRoot, leaf)
        const compatibilities = leaf.data().compatibilities
        selfCy.blur().focus(leaf)
        otherCy
          .blur()
          .focus(otherCy.nodes().filter(node => +node.data().id in compatibilities))
        this.setState({ leftFocus: selfSegment, rightFocus: null })
      },
    }
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

    // segments are linear sequences of nodes given by a top and bottom
    let selfSegment

    if (segmentSelect) {
      // if we're selecting a segment, choose the corresponding segment
      selfSegment = Segment.fromRange(self.getRangeOf(ev.target))
      self.blur().focusRange(self.getRangeOf(ev.target))
    } else {
      // otherwise, bail out if we're not on a leaf
      if (ev.target.outgoers().length !== 0) return
      // and choose the full branch, if we are on a leaf
      const selfRoot = ev.cy.nodes().roots()[0]
      selfSegment = new Segment(selfRoot, ev.target)
      self.blur().focus(ev.target)
    }

    // unconditionally focus the clicked segment
    if (isLeft) this.setState({ leftFocus: selfSegment })
    else this.setState({ rightFocus: selfSegment })

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
          otherSegment = Segment.fromRange(otherRange)
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
          otherSegment = new Segment(otherRoot, other.loci)
        }
      }

      if (otherSegment) {
        // if we picked out a corresponding segment, focus it.
        if (isLeft) this.setState({ rightFocus: otherSegment })
        else this.setState({ leftFocus: otherSegment })
      } else {
        //otherwise clear the focus
        if (isLeft) this.setState({ rightFocus: null, leftFocus: selfSegment })
        else this.setState({ leftFocus: null, rightFocus: selfSegment })
      }
    }
  }

  getJSON() {
    return JSON.stringify({
      pre: {
        data: JSON.parse(this.cy1.orig),
        name: this.state.prelabel
      },
      post: {
        data: JSON.parse(this.cy2.orig),
        name: this.state.postlabel
      }
    })
  }


  setStatus(status) { this.setState({ status }) }

  regenerateFocus() {
    const connectedLeft = this.cy1.cy.loci?.filter(node => node.inside())
    const connectedRight = this.cy2.cy.loci?.filter(node => node.inside())

    if (connectedLeft?.length == 0 || connectedRight?.length == 0) {
      // we just throw away the focus if all the loci on either side have been filtered out
      this.cy1.cy.blur()
      this.cy2.cy.blur()
      this.setState({ leftFocus: null, rightFocus: null })
    } else {
      this.setState({
        leftFocus: this.state.leftFocus ? new Segment(this.cy1.cy.root, this.cy1.cy.loci) : null,
        rightFocus: this.state.rightFocus ? new Segment(this.cy2.cy.root, this.cy2.cy.loci) : null,
      })
    }
    // we sometimes need to regenerate focus, 
    // so that the assembly diff is regenerated, 
    // so that its lines are properly mapped on to the merged nodes.
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
    Object.assign(cy, checkedMixin);
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
          this.setState({ leftFocus: null, rightFocus: null })
          this.tooltip.current.clearTooltip()
        })
      }
    })

    cy.on('zoom pan', () => {
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

  resetLayout(layout, view) {
    this.setState(oldState => {
      this.cy1.currentLayout.stop()
      this.cy2.currentLayout.stop()
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
          // we need to restore the tidiness level and the pruning to the
          // reconstucted graph
          this.viewMenu.current.retidy()
          this.pruneMenu.current.doPrune()
        } else {
          //no view given, we're just recomputing the view,
          view = oldState.view
        }
      }
      this.cy1.currentLayout = this.cy1.cy.layout(layout).run()
      this.cy2.currentLayout = this.cy2.cy.layout(layout).run()

      return { view, layout }
    })
  }

  refreshLayout() {
    this.cy1.currentLayout = this.cy1.cy.layout(this.state.layout).run()
    this.cy2.currentLayout = this.cy2.cy.layout(this.state.layout).run()
  }

  clearTooltip() {
    this.tooltip.current.clearTooltip()
  }

  render(_props, state) {
    // TODO I could get rid of a lot of lambdas here if I properly bound "this"
    // in some of these methods
    return html`
      <${Tooltip} ref=${this.tooltip}/>
      <${MenuBar} 
        cyLeft=${this.cy1}
        cyRight=${this.cy2}
        view=${state.view}
        layout=${state.layout}
        getReportInterface=${() => this.getReportInterface()}
        regenerateFocus=${() => this.regenerateFocus()}
        resetLayout=${this.resetLayout}
        refreshLayout=${() => this.refreshLayout()}
        tidiness=${state.tidiness}
        status=${state.status}
        batch=${cb => this.batch(cb)}
        viewMenu=${this.viewMenu}
        pruneMenu=${this.pruneMenu}
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
