import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, render, createRef } from 'https://unpkg.com/preact@latest?module'
import cytoscape from "https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm"
import Tooltip from './tooltip.js';
import DiffPanel from './diffPanel.js';
import MenuBar from './menuBar.js';
import { focusMixin } from './focusMixin.js';
import * as GraphStyle from './graphStyle.js' ;
import { tidyGraph, removeBranch } from './graph-tidy.js';

const standardLayout = { name: 'breadthfirst', directed: true, spacingFactor: 2 }

class App extends Component {

  constructor() {
    super();
    this.state = {
      status: null, // idle
      tidiness: "untidy", // we're not yet tidying anything
      showingSyscalls: true, // we start with syscalls visible
      showingSimprocs: true, // we start with SimProcedure calls visible
    }
    this.cy1 = createRef()
    this.cy2 = createRef()
    this.tooltip = createRef()
    this.diffPanel = createRef()
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
    if (!this.cy1.cy || !this.cy2.cy) {
      alert("Please load both graphs before attempting comparison.")
      return
    }
    const isLeft = ev.target.cy() == this.cy1.cy
    const self = isLeft ? this.cy1.cy : this.cy2.cy
    const other = isLeft ? this.cy2.cy : this.cy1.cy
    this.tooltip.current.attachTo(ev.target)
    // if the node is already focused, but other nodes are focused as well,
    // we're refining a previous selection. In
    // this case, we narrow the focus to just the clicked node.
    if (self.loci?.length > 1 && self.loci.includes(ev.target)) {
      self.blur().focus(ev.target)
      if (isLeft) this.diffPanel.current.setLeftFocus(ev.target)
      else this.diffPanel.current.setRightFocus(ev.target)
    }
    // otherwise, we're starting a new selection. In this case, we focus the
    // node and all its compatibilities from the other graph.
    else {
      self.blur().focus([ev.target])
      other.blur()
        .focus(other.nodes().filter(node => +node.data().id in ev.target.data().compatibilities))
      if (Object.keys(ev.target.data().compatibilities).length == 1) {
        const theId = Object.keys(ev.target.data().compatibilities)[0]
        if (isLeft) this.diffPanel.current.setBothFoci(ev.target, other.nodes(`#${theId}`))
        else this.diffPanel.current.setBothFoci(other.nodes(`#${theId}`), ev.target)
      } else {
        if (isLeft) this.diffPanel.current.resetLeftFocus(ev.target)
        else this.diffPanel.current.resetRightFocus(ev.target)
      }
    }
  }

  refresh() {
    this.cy1.cy.json({ elements: JSON.parse(this.cy1.orig).elements })
    this.cy2.cy.json({ elements: JSON.parse(this.cy2.orig).elements })
    // refocus all foci, and reset viewport
    this.cy1.cy.refocus().fit()
    this.cy2.cy.refocus().fit()
    this.setState({ status: null })
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
    this.setState({ status: null })
  }

  toggleSyscalls() {
    this.setState(oldState => {
      GraphStyle.settings.showingSyscalls = !oldState.showingSyscalls;
      this.cy1.cy.style().update()
      this.cy2.cy.style().update()
      return {showingSyscalls: !oldState.showingSyscalls}
    })
  }

  toggleSimprocs() {
    this.setState(oldState => {
      GraphStyle.settings.showingSimprocs = !oldState.showingSimprocs;
      this.cy1.cy.style().update()
      this.cy2.cy.style().update()
      return {showingSimprocs: !oldState.showingSimprocs}
    })
  }

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
    const cy = cytoscape({
      style: GraphStyle.style,
      elements: raw.elements
    })

    // mount to DOM
    cy.mount(ref.current)
    // monkeypatch in additional methods
    Object.assign(cy, focusMixin);
    // set layout
    cy.layout(standardLayout).run()
    // Accumulate assembly at leaves
    for (const leaf of [...cy.nodes().leaves()]) {
      let assembly = "";
      for (const node of leaf.predecessors('node').reverse()) {
        assembly += node.data().contents + '\n'
      }
      assembly += leaf.data().contents
      leaf.data().assembly = assembly
    }
    cy.nodes().map(node => this.initializeNode(node, cy))
    cy.on('add', ev => {
      if (ev.target.group() === 'nodes') {
        this.initializeNode(ev.target, cy)
      }
    })

    // clear focus on click without target
    cy.on('click', ev => {
      if (!ev.target.group) {
        this.batch(() => {
          this.cy1.cy.blur()
          this.cy2.cy.blur()
          this.tooltip.current.clearTooltip()
        })
      }
    })

    // stow graph data in reference
    ref.cy = cy
    ref.orig = JSON.stringify(cy.json())
    this.setState({ status: null })
  }

  initializeNode(node, cy) {

    // turn off manual graph dragging
    node.ungrabify()

    // add methods for actively querying display features

    // mouseover handling
    node.on('mouseout', () => {
      cy.container().style.cursor = "default"
    })

    node.on('mouseover', ev => {
      if (ev.target.outgoers().length == 0) {
        cy.container().style.cursor = "pointer"
      }
      if (cy.loci && !ev.target.hasClass('pathHighlight')) return;
      this.tooltip.current.attachTo(ev.target)
    })

    node.leaves().on('click',
      ev => this.handleClick(ev))
  }

  startRender(method) {
    this.setState({ status: "rendering" }, method)
  }

  batch(cb) {
    this.cy1.cy.startBatch()
    this.cy2.cy.startBatch()
    cb()
    this.cy1.cy.endBatch()
    this.cy2.cy.endBatch()
  }

  async setTidiness(tidiness) {
    // we insert a few milliseconds delay to allow for prior state updates to
    // render
    await new Promise(r => setTimeout(r, 50))
    switch (tidiness) {
      case "untidy": {
        this.refresh()
        break;
      }
      case "tidy": {
        if (this.state.tidiness == "very-tidy") {
          // if we're already very tidy, we need to refresh and then merge nodes
          // from there.
          this.batch(() => {
            this.refresh()
            this.tidy({})
          })
        }
        else this.tidy({})
        break;
      }
      case "very-tidy": {
        this.batch(() => {
          this.refresh()
          this.tidy({ mergeConstraints: true })
        })
        break;
      }
    }
    this.setState({ tidiness, status: null })
  }

  resetLayout() {
    this.batch(() => {
      this.cy1.cy.layout(standardLayout).run()
      this.cy2.cy.layout(standardLayout).run()
    })
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

  render(_props, state) {
    // TODO I could get rid of a lot of lambdas here if I properly bound "this"
    // in some of these methods
    return html`
      <${Tooltip} ref=${this.tooltip}/>
      <${MenuBar} 
        setTidiness=${level => this.startRender(() => this.setTidiness(level))}
        prune=${relation => this.prune(relation)}
        resetLayout=${() => this.resetLayout()}
        tidiness=${state.tidiness}
        showingSyscalls=${state.showingSyscalls}
        showingSimprocs=${state.showingSimprocs}
        toggleSyscalls=${() => this.toggleSyscalls()}
        toggleSimprocs=${() => this.toggleSimprocs()}
      />
      <div id="main-view">
        <div 
          onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
          onDragover=${ev => this.handleDragover(ev)}
          onDragleave=${ev => this.handleDragleave(ev)}
          onDrop=${ev => this.startRender(() => this.handleDrop(ev, this.cy1))} 
          ref=${this.cy1} id="cy1">
            <span id="labelLeft">prepatch</span>
        </div>
        <div 
          onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
          onDragover=${ev => this.handleDragover(ev)}
          onDragleave=${ev => this.handleDragleave(ev)}
          onDrop=${ev => this.startRender(() => this.handleDrop(ev, this.cy2))}
          ref=${this.cy2} id="cy2">
            <span id="labelRight">postpatch</span>
        </div>
      </div>
      <${DiffPanel} 
        onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
        ref=${this.diffPanel}/>
      ${state.status == "rendering" && html`<span id="render-indicator">rendering...</span>`}
    `
  }
}

render(html`<${App}/>`, document.body);
