import * as Diff from 'https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm'
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { getNodesFromEnds, getEdgesFromEnds } from '../util/segmentation.js'

export default class DiffPanel extends Component {
  constructor() {
    super();
    this.state = {
      mode: null,
    }
  }

  toggleMode(mode) {
    if (this.state.mode == mode) {
      this.setState({ mode: null })
    } else {
      this.setState({ mode })
    }
  }

  render(props, state) {
    const assemblyAvailable = props.leftFocus || props.rightFocus
    const registersAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()].regdiff
    const memoryAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()].memdiff
    const concretionAvailable = props.leftFocus && props.rightFocus &&
      props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()].conc_args
    const actionsAvailable = 
      props.rightFocus?.top.outgoers("edge")[0]?.data().actions?.length > 0 ||
      props.leftFocus?.top.outgoers("edge")[0]?.data().actions?.length > 0
    return html`<div id="diff-panel" onMouseEnter=${props.onMouseEnter}>
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

  hunkFormat(hunk, className) {
    const terminator = hunk.slice(-1)
    if (terminator === '>') {
      const newHunk = hunk.slice(0,hunk.length - 1)
      return html`<span class=${className}>${newHunk}</span>${terminator} `
    } else {
      return html`<span class=${className}>${hunk}</span> `
    }

  }

  diffWords(leftLine,rightLine) {
  
    const lwords = leftLine.split(/\s+/)
    const rwords = rightLine.split(/\s+/)

    const laddr = lwords.shift()
    const raddr = rwords.shift()

    const comparison = lwords.map((lw,idx) => rwords[idx] === lw)
  
    leftLine = lwords
      .map((w,idx) => comparison[idx] ? `${w} ` : this.hunkFormat(w,"hunkRemoved"))
    rightLine = rwords
      .map((w,idx) => comparison[idx] ? `${w} ` : this.hunkFormat(w,"hunkAdded"))

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
    let [,...results] = s.slice(1,-1).split(/\s+/);
    results = results.map(s => {
      switch (s) {
        case "---->>" : return "→"
        case "<<----" : return "←"
        default : return s
      }
    })
    return results.join(' ')
  }

  render(props) {
    return html`<${LineDiffView} 
      leftLines=${props.leftFocus ? this.getActions(props.leftFocus) : null}
      rightLines=${props.rightFocus ? this.getActions(props.rightFocus) : null}
      comparator=${(l, r) => this.compare(l, r)}
      diffWords=${(l, r) => this.diffWords(l, r)}
      highlight=${(idLeft, idRight) => this.highlightNodes(idLeft,idRight)}
      format=${s => this.format(s)}
      dim=${() => this.dimAll()}
    />`
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
          const addr = parseInt(line.match(/^[0-9a-f]*/),16)
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
    return lmnemonic == rmnemonic && loperands.every((lop, idx) => lop == roperands[idx])
  }

  render(props) {
    return html`<${LineDiffView} 
      leftLines=${props.leftFocus ? this.getAssembly(props.leftFocus) : null}
      rightLines=${props.rightFocus ? this.getAssembly(props.rightFocus) : null}
      comparator=${(l, r) => this.compare(l, r)}
      highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
      dim=${() => this.dimAll()}
    />`
  }
}

class LineDiffView extends Component {
  getLeftContents() {
    if (this.props.leftLines) {
      if (this.props.rightLines) return this.diffLines().left
      const lines = this.props.leftLines.contents
      return lines
        .split('\n')
        .map(line => this.props.format?.(line) || line)
        .join('\n')
    }
    return null
  }

  getRightContents() {
    if (this.props.rightLines) {
      if (this.props.leftLines) return this.diffLines().right
      else {
        const lines = this.props.rightLines.contents
        return lines
          .split('\n')
          .map(line => this.props.format?.(line) || line)
          .join('\n')
          .trim()
      }
    }
    return null
  }

  diffLines() {
    // simple memoization
    if (this.prevLeftLines == this.props.leftLines &&
      this.prevRightLines == this.props.rightLines) {
      return { left: this.prevLeftDiff, right: this.prevRightDiff }
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

    const diffs = Diff.diffLines(leftContents, rightContents, {
      comparator: this.props.comparator
    })
    let renderedRight = []
    let renderedLeft = []
    let curLeft = 0
    let curRight = 0

    let toHunk = (curLeft, curRight, content, theclass, left) => html`<div
        title=${left ? leftMsgs[curLeft] : rightMsgs[curRight]}
        onMouseEnter=${() => this.props.highlight(leftIds[curLeft], rightIds[curRight])} 
        onMouseLeave=${this.props.dim}
        class=${theclass}>${content}
      </div>`

    for (const diff of diffs) {
      if (diff?.added) {
        for (const line of diff.value.split('\n')) {
          if (line == "") continue
          const hunkRight = toHunk(curLeft,curRight,this.props.format?.(line) || line, "hunkAdded")
          const hunkLeft = toHunk(curLeft,curRight,null,null,true)
          curRight++
          renderedRight.push(hunkRight)
          renderedLeft.push(hunkLeft)
        }
      } else if (diff?.removed) {
        for (const line of diff.value.split('\n')) {
          if (line == "") continue
          const hunkRight = toHunk(curLeft,curRight,null,null)
          const hunkLeft = toHunk(curLeft,curRight,this.props.format?.(line) || line, "hunkRemoved",true)
          curLeft++
          renderedRight.push(hunkRight)
          renderedLeft.push(hunkLeft,true)
        }
      } else {
        for (let i = 0; i < diff.count; i++) {
          let rightLine = this.props.format?.(rightLines[curRight]) || rightLines[curRight]
          let leftLine = this.props.format?.(leftLines[curLeft]) || leftLines[curLeft];
          [leftLine,rightLine] = this.props.diffWords?.(leftLine, rightLine) || [leftLine,rightLine]
          const hunkRight = toHunk(curLeft,curRight,rightLine,null)
          const hunkLeft = toHunk(curLeft,curRight,leftLine,null)
          curRight++
          curLeft++
          renderedRight.push(hunkRight)
          renderedLeft.push(hunkLeft,true)
        }
      }
    }

    this.prevLeftDiff = renderedLeft
    this.prevRightDiff = renderedRight

    return { left: this.prevLeftDiff, right: this.prevRightDiff }
  }

  render() {
    return html` <div id="asm-diff-data">
      <pre id="asmViewLeft">${this.getLeftContents()}</pre>
      <pre id="asmViewRight">${this.getRightContents()}</pre>
    </div>`
  }
}

class RegisterDifference extends Component {

  constructor() {
    super();
    this.state = { view: "symbolic" }
  }

  setView(view) {
    this.setState({ view })
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
        setView=${view => this.setView(view)} 
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

  setView(view) {
    this.setState({ view })
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const addresses = []
    const conc_adiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_memdiff ?? []
    const adiffs = state.view === "symbolic"
      ? props.leftFocus.bot.data().compatibilities[rightId].memdiff
      : conc_adiffs[state.view]
    for (const reg in adiffs) {
      addresses.push(html`
        <span class="grid-diff-left">${adiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${adiffs[reg][1]}</span>`)
    }
    return html`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${view => this.setView(view)} 
        concretionCount=${conc_adiffs.length}/>
      <div id="grid-diff-data"> ${addresses.length > 0
        ? addresses
        : html`<span class="no-difference">no memory differences detected ✓</span>`
      }</div></div>`
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
