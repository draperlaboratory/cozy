import * as Diff from 'https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm'
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import { getNodesFromEnds, getEdgesFromEnds } from '../util/segmentation.js'

export default class DiffPanel extends Component {
  constructor() {
    super();
    this.state = {
      mode: null,
    }
    
    this.diffPanel = createRef()
    this.dragHandle = createRef()
  }

  toggleMode(mode) {
    if (this.state.mode == mode) {
      this.setState({ mode: null })
    } else {
      this.setState({ mode })
    }
  }

  startResize(e) {
    this.diffPanel.current.onpointermove = e => {
      this.diffPanel.current.style.maxHeight = `${Math.max(50, window.innerHeight - e.clientY)}px`
    }
    this.dragHandle.current.setPointerCapture(e.pointerId)
    this.dragHandle.current.classList.add("grabbed")
    this.diffPanel.current.classList.add("resizing")
  }

  stopResize(e) {
    this.diffPanel.current.onpointermove = null
    this.dragHandle.current.releasePointerCapture(e.pointerId)
    this.dragHandle.current.classList.remove("grabbed")
    this.diffPanel.current.classList.remove("resizing")
  }

  render(props, state) {
    const assemblyAvailable = props.leftFocus || props.rightFocus
    const registersAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.regdiff
    const memoryAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.memdiff
    const concretionAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.conc_args
    const actionsAvailable =
      props.rightFocus?.top.outgoers("edge")[0]?.data().actions?.length > 0 ||
      props.leftFocus?.top.outgoers("edge")[0]?.data().actions?.length > 0
    const sideEffectsAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.conc_sediff
    return html`<div id="diff-panel" onMouseEnter=${props.onMouseEnter} ref=${this.diffPanel}>
      <div id="diff-drag-handle"
        onPointerDown=${e => this.startResize(e)} 
        onPointerUp=${e => this.stopResize(e)} 
        ref=${this.dragHandle}
      />
      <div>
        <button 
          disabled=${!assemblyAvailable}
          onClick=${() => this.toggleMode("assembly")}>
          Assembly
        </button>
        <button 
          disabled=${!memoryAvailable}
          onClick=${() => this.toggleMode("memory")}>
          Memory
        </button>
        <button disabled=${!registersAvailable}
          onClick=${() => this.toggleMode("registers")}>
          Registers
        </button>
        <button disabled=${!concretionAvailable}
          onClick=${() => this.toggleMode("concretions")}>
          Concretions
        </button>
        <button disabled=${!actionsAvailable}
          onClick=${() => this.toggleMode("actions")}>
          Events
        </button>
        <button disabled=${!sideEffectsAvailable}
          onClick=${() => this.toggleMode("side-effects")}>
          Side Effects
        </button>
      </div>
      ${state.mode == "assembly" && assemblyAvailable && html`
        <${AssemblyDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "registers" && registersAvailable && html`
        <${RegisterDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "memory" && memoryAvailable && html`
        <${MemoryDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "concretions" && concretionAvailable && html`
        <${Concretions} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "actions" && actionsAvailable && html`
        <${ActionDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      ${state.mode == "side-effects" && sideEffectsAvailable && html`
        <${SideEffectDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`
      }
      </div>`
  }
}

class ActionDifference extends Component {
  getActions(focus) {
    const segment = getEdgesFromEnds(focus.top, focus.bot).reverse()
    let contents = ""
    let msg = ""
    const lines = []
    const ids = []
    const msgs = []

    for (const edge of segment) {
      const id = edge.id()
      for (const line of edge.data().actions) {
        contents += line + '\n'
        lines.push(line)
        msgs.push(msg)
        ids.push(id)
      }
    }

    return { contents, lines, ids, msgs }
  }

  onInput(e) {
    this.setState({ filterExpr: e.target.value })
  }

  diffWords(leftLine, rightLine) {

    const lwords = leftLine.split(/\s+/)
    const rwords = rightLine.split(/\s+/)

    const laddr = lwords.shift()
    const raddr = rwords.shift()

    const comparison = lwords.map((lw, idx) => rwords[idx] === lw)

    leftLine = lwords
      .map((w, idx) => comparison[idx] ? `${w} ` : hunkFormat(w, "hunkRemoved"))
    rightLine = rwords
      .map((w, idx) => comparison[idx] ? `${w} ` : hunkFormat(w, "hunkAdded"))

    leftLine.unshift(`${laddr} `)
    rightLine.unshift(`${raddr} `)

    return [leftLine, rightLine]
  }

  highlightNodes(idLeft, idRight) {
    const cyLeft = this.props.leftFocus.top.cy()
    const cyRight = this.props.rightFocus.top.cy()
    cyLeft.highlight(cyLeft.edges(`#${idLeft}`).source())
    cyRight.highlight(cyRight.edges(`#${idRight}`).source())
  }

  dimAll() {
    this.props.leftFocus.top.cy().dim()
    this.props.rightFocus.top.cy().dim()
  }

  compare(l, r) {
    // TODO: more fleshed out comparator, case split on action type
    const [, , laction, ...lterms] = l.split(/\s+/);
    const [, , raction, ...rterms] = r.split(/\s+/);
    if (laction === raction) {
      switch (laction) {
        case "reg/write:": return lterms[0] == rterms[0] && lterms.length === rterms.length
        case "reg/read:": return lterms[0] == rterms[0] && lterms.length === rterms.length
        default: return lterms.length === rterms.length
      }
    }
    return false
  }

  format(s) {
    let [, ...results] = s.slice(1, -1).split(/\s+/);
    results = results.map(s => {
      switch (s) {
        case "---->>": return "→"
        case "<<----": return "←"
        default: return s
      }
    })
    return results.join(' ')
  }

  render(props, state) {
    return html`<div id="action-diff">
      <${SearchInput} onInput=${e => this.onInput(e)} value=${this.filterExpr}/>
      <${LineDiffView} 
      filterExpr=${state.filterExpr}
      leftLines=${props.leftFocus ? this.getActions(props.leftFocus) : null}
      rightLines=${props.rightFocus ? this.getActions(props.rightFocus) : null}
      comparator=${(l, r) => this.compare(l, r)}
      diffWords=${(l, r) => this.diffWords(l, r)}
      highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
      format=${s => this.format(s)}
      dim=${() => this.dimAll()}
      />
      </div>
      `
  }
}

class AssemblyDifference extends Component {

  getAssembly(focus) {
    const segment = getNodesFromEnds(focus.top, focus.bot).reverse()
    let contents = ""
    let msg = ""
    const lines = []
    const ids = []
    const msgs = []
    const debug = focus.top.cy().debugData

    for (const node of segment) {
      const id = node.id()
      for (const line of node.data().contents.split('\n')) {
        if (debug) {
          const addr = parseInt(line.match(/^[0-9a-f]*/), 16)
          if (debug[addr]) msg = "" // start fresh list of debug locations
          for (const loc of debug[addr] || []) msg += loc + '\n'
        }
        contents += line + '\n'
        lines.push(line)
        msgs.push(msg)
        ids.push(id)
      }
    }

    return { contents, lines, ids, msgs }
  }

  onInput(e) {
    this.setState({ filterExpr: e.target.value })
  }

  highlightNodes(idLeft, idRight) {
    const cyLeft = this.props.leftFocus.top.cy()
    const cyRight = this.props.rightFocus.top.cy()
    cyLeft.highlight(cyLeft.nodes(`#${idLeft}`))
    cyRight.highlight(cyRight.nodes(`#${idRight}`))
  }

  dimAll() {
    this.props.leftFocus.top.cy().dim()
    this.props.rightFocus.top.cy().dim()
  }

  compare(l, r) {
    // TODO --- count lines with identical mnemonics and numbers of operands as
    // the same, and do a word-level diff.
    const [, lmnemonic, ...loperands] = l.split(/\s+/);
    const [, rmnemonic, ...roperands] = r.split(/\s+/);
    return lmnemonic == rmnemonic && loperands.length == roperands.length
  }

  diffWords(leftLine, rightLine) {

    const lwords = leftLine.split(/\s+/)
    const rwords = rightLine.split(/\s+/)

    const laddr = lwords.shift()
    const raddr = rwords.shift()

    const comparison = lwords.map((lw, idx) => rwords[idx] === lw)

    leftLine = lwords
      .map((w, idx) => comparison[idx] ? `${w} ` : hunkFormat(w, "hunkRemoved"))
    rightLine = rwords
      .map((w, idx) => comparison[idx] ? `${w} ` : hunkFormat(w, "hunkAdded"))

    leftLine.unshift(`${laddr} `)
    rightLine.unshift(`${raddr} `)

    return [leftLine, rightLine]
  }

  render(props, state) {
    return html`<div id="assembly-diff">
      <${SearchInput} value=${state.filterExpr} onInput=${e => this.onInput(e)}/>
      <${LineDiffView} 
      filterExpr=${state.filterExpr}
      leftLines=${props.leftFocus ? this.getAssembly(props.leftFocus) : null}
      rightLines=${props.rightFocus ? this.getAssembly(props.rightFocus) : null}
      comparator=${(l, r) => this.compare(l, r)}
      diffWords=${(l, r) => this.diffWords(l, r)}
      highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
      dim=${() => this.dimAll()}
    />
    </div>`
  }
}

function SearchInput({ value, onInput }) {
  return html`<div class="search-input">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input value="${value}" onInput=${onInput}></input>
      </div>`
}

class LineDiffView extends Component {
  getContents() {
    if (!this.props.leftLines && !this.props.rightLines) return null
    if (!this.props.rightLines) {
      const {
        lines: leftLines,
        ids: leftIds,
        msgs: leftMsgs,
      } = this.props.leftLines
      const hunkCtx = { leftIds, rightIds: [""], leftMsgs, rightMsgs: [""] }
      return leftLines
        .map((line, idx) => Hunk({
          hunkCtx,
          curLeft: idx,
          curRight: 0,
          leftContent: this.props.format?.(line) || line,
          rightContent: " ",
        }))
    }
    if (!this.props.leftLines) {
      const {
        lines: rightLines,
        ids: rightIds,
        msgs: rightMsgs,
      } = this.props.rightLines
      const hunkCtx = { rightIds, leftIds: [""], rightMsgs, leftMsgs: [""] }
      return rightLines
        .map((line, idx) => Hunk({
          hunkCtx,
          curLeft: 0,
          curRight: idx,
          leftContent: " ",
          rightContent: this.props.format?.(line) || line,
        }))
    }
    return this.diffLines()
  }

  diffLines() {
    // simple memoization
    if (this.prevLeftLines == this.props.leftLines &&
      this.prevRightLines == this.props.rightLines) {
      return this.prevDiff
    }

    this.prevLeftFocus = this.props.leftFocus
    this.prevRightFocus = this.props.rightFocus

    const {
      contents: leftContents,
      lines: leftLines,
      ids: leftIds,
      msgs: leftMsgs,
    } = this.props.leftLines

    const {
      contents: rightContents,
      lines: rightLines,
      ids: rightIds,
      msgs: rightMsgs,
    } = this.props.rightLines

    const hunkCtx = { leftIds, leftMsgs, rightIds, rightMsgs }
    const diffs = Diff.diffLines(leftContents, rightContents, {
      comparator: this.props.comparator
    })
    let rendered = []
    let curLeft = 0
    let curRight = 0
    let mkHunk = ({ curLeft, curRight, leftContent, rightContent, leftClass, rightClass }) => Hunk({
      highlight: this.props.highlight 
        ? () => this.props.highlight(leftIds[curLeft], rightIds[curRight])
        : () => {},
      dim: this.props.dim
        ? () => this.props.dim()
        : () => {},
      hunkCtx,
      curLeft,
      curRight,
      leftContent,
      rightContent,
      leftClass,
      rightClass,
    })

    for (const diff of diffs) {
      if (diff?.added) {
        for (const line of diff.value.split('\n')) {
          if (line == "") continue
          const hunk = mkHunk({
            curLeft,
            curRight,
            leftContent: " ",
            rightContent: this.props.format?.(line) || line,
            rightClass: "hunkAdded",
          })
          curRight++
          rendered.push(hunk)
        }
      } else if (diff?.removed) {
        for (const line of diff.value.split('\n')) {
          if (line == "") continue
          const hunk = mkHunk({
            curLeft,
            curRight,
            leftContent: this.props.format?.(line) || line,
            rightContent: " ",
            leftClass: "hunkRemoved",
          })
          curLeft++
          rendered.push(hunk)
        }
      } else {
        for (let i = 0; i < diff.count; i++) {
          let rightContent = this.props.format?.(rightLines[curRight]) || rightLines[curRight]
          let leftContent = this.props.format?.(leftLines[curLeft]) || leftLines[curLeft];
          [leftContent, rightContent] = this.props.diffWords?.(leftContent, rightContent) || [leftContent, rightContent]
          const hunk = mkHunk({
            curLeft,
            curRight,
            leftContent,
            rightContent,
          })
          curRight++
          curLeft++
          rendered.push(hunk)
        }
      }
    }

    this.prevDiff = rendered

    return rendered
  }

  render(props) {
    const hunks = this.getContents().filter(({ contentListing }) => {
      if (!props.filterExpr) return true
      let lineFilter
      try {
        lineFilter = new RegExp(props.filterExpr)
      } catch (e) {
        lineFilter = /^/
      }

      return lineFilter.test(contentListing.left) ||
        lineFilter.test(contentListing.right)
    })

    return html`<pre id="line-diff-data-view">${hunks}</pre>`
  }
}


function hunkFormat(hunk, className) {
  const terminator = hunk.slice(-1)
  if (terminator === '>' || terminator == ',') {
    const newHunk = hunk.slice(0, hunk.length - 1)
    return html`<span class=${className}>${newHunk}</span>${terminator} `
  } else {
    return html`<span class=${className}>${hunk}</span> `
  }

}


function Hunk({ dim, highlight, hunkCtx, curLeft, curRight, leftContent, leftClass, rightContent, rightClass }) {
  const hunk = html`<div
        onMouseEnter=${highlight} 
        onMouseLeave=${dim}
        >
        <div
          title=${hunkCtx?.leftMsgs[curLeft]}
          class=${leftClass}
        >${leftContent}</div>
        <div
          title=${hunkCtx?.rightMsgs[curRight]}
          class=${rightClass}
        >${rightContent}</div>
      </div>`

  hunk.contentListing = { left: leftContent, right: rightContent }

  return hunk
}

class RegisterDifference extends Component {

  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const registers = []
    const conc_regdiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_regdiff ?? []
    const rdiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].regdiff
      : conc_regdiffs[state.view]
    for (const reg in rdiffs) {
      registers.push(html`
        <span class="grid-diff-left">${rdiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${rdiffs[reg][1]}</span>`)
    }
    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_regdiffs.length}/>
      <div id="grid-diff-data"> ${registers.length > 0
        ? registers
        : html`<span class="no-difference">no register differences detected ✓</span>`
      }</div></div>`
  }
}

class MemoryDifference extends Component {
  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const addresses = []
    const conc_adiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_memdiff ?? []
    const adiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].memdiff
      : conc_adiffs[state.view]
    for (const addr in adiffs) {
      const addrparts = addr
        .split('\n')
        .map(part => [part, html`<br/>`])
        .flat()
      addresses.push(html`
        <span class="grid-diff-left">${adiffs[addr][0]}</span>
        <span class="grid-diff-label">${addrparts}</span>
        <span class="grid-diff-right">${adiffs[addr][1]}</span>`)
    }
    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${conc_adiffs.length}/>
      <div id="grid-diff-data"> ${addresses.length > 0
        ? addresses
        : html`<span class="no-difference">no memory differences detected ✓</span>`
      }</div></div>`
  }
}

class SideEffectDifference extends Component {
  constructor() {
    super();
    this.state = { view: 0 }
  }

  diffableSideEffects(effects, presence) {
      
    let contents = ""
    let msg = ""
    let effectIdx = 0
    const lines = []
    const ids = []
    const msgs = []

    for (const isPresent of presence) {
      if (isPresent) {
        contents += effects[effectIdx].body + '\n'
        lines.push(effects[effectIdx].body)
        ids.push(effects[effectIdx].id)
        effectIdx++
      } else {
        contents += '\n'
        lines.push("")
        ids.push(null)
      }
      msgs.push(msg)
    }

    return { contents, lines, ids, msgs }
  }

  highlightNodes(idLeft, idRight) {
    const cyLeft = this.props.leftFocus.top.cy()
    const cyRight = this.props.rightFocus.top.cy()
    if (idLeft) cyLeft.highlight(cyLeft.nodes(`#${idLeft}`))
    if (idRight) cyRight.highlight(cyRight.nodes(`#${idRight}`))
  }

  dimAll() {
    this.props.leftFocus.top.cy().dim()
    this.props.rightFocus.top.cy().dim()
  }

  diffWords(leftLine, rightLine) {

    const diffs = Diff.diffWords(leftLine, rightLine)
    const newLeft = []
    const newRight = []

    for (const diff of diffs) {
      if (diff?.added) {
        newRight.push(html`<span class="hunkAdded">${diff.value}</span>`)
      }
      else if (diff?.removed) {
        newLeft.push(html`<span class="hunkRemoved">${diff.value}</span>`)
      } else {
        newRight.push(html`<span>${diff.value}</span>`)
        newLeft.push(html`<span>${diff.value}</span>`)
      }
    }

    return [newLeft, newRight]
  }


  render(props, state) {

    const rightId = props.rightFocus.bot.id()
    const concretions = props.leftFocus.bot.data().compatibilities[rightId].conc_sediff ?? []
    const conc_sediffs = concretions[state.view]
    const presence = props.leftFocus.bot.data().compatibilities[rightId].sediff ?? {}
    const chandivs = []

    // Note, line-diffing is handled on the python side, because of the
    // complexity of diffing non-concrete side effects. Hence, we have
    // a trivial comparator here.
    for (const channel in conc_sediffs) {
      if (!(channel in presence)) continue
      const chandiv = html`<div class="side-effect-channel">
        <h3>${channel}</h3>
        <${LineDiffView} 
          leftLines=${this.diffableSideEffects(
            conc_sediffs[channel].left, 
            presence[channel].map(([x,]) => x)
          )}
          rightLines=${this.diffableSideEffects(
            conc_sediffs[channel].right, 
            presence[channel].map(([,y]) => y)
          )}
          diffWords=${(l,r) => this.diffWords(l,r)}
          comparator=${() => true}
          highlight=${(idLeft,idRight) => this.highlightNodes(idLeft, idRight)}
          dim=${() => this.dimAll()}
        />
      </div>`
      chandivs.push(chandiv)
    }

    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setState({ view })} 
        concretionCount=${concretions.length}/>
      ${chandivs}
      </div>`
  }

}

class Concretions extends Component {
  render(props) {
    const rightId = props.rightFocus.bot.id()
    const examples = []
    const concretions = props.leftFocus.bot.data().compatibilities[rightId].conc_args

    for (const concretion of concretions) {
      examples.push(html`
        <pre class="concrete-example">${JSON.stringify(concretion, undefined, 2)}</pre>
      `)
    }

    return html`<div id="concretion-header">
      Viewing ${concretions.length} concrete input examples
    </div>
    <div id="concretion-data">
      ${examples}
    </div>`
  }
}

class ConcretionSelector {
  render(props) {

    if (props.concretionCount === 0) return null

    const buttons = [html`<button 
      data-selected=${props.view == "symbolic"} 
      onClick=${() => props.setView("symbolic")}
      >Symbolic</button>`
    ]

    for (let i = 0; i < props.concretionCount; i++) {
      buttons.push(html`<button 
        data-selected=${props.view == i} 
        onClick=${() => props.setView(i)}
        >Example ${i + 1}</button>`
      )
    }

    return html`<div class="subordinate-buttons">${buttons}</div>`
  }
}
