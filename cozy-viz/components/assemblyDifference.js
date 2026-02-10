import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { hunkFormat } from './hunk.js'
import SearchInput from './searchInput.js'
import LineDiffView from './lineDiffView.js'
import { getNodesFromEnds } from '../util/segmentation.js'

export default class AssemblyDifference extends Component {

  getAssembly(focus) {
    const segment = getNodesFromEnds(focus.top, focus.bot).reverse()
    let contents = ""
    let msg = ""
    const lines = []
    const ids = []
    const msgs = []
    const debug = focus.cy().debugData

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
    const cyLeft = this.props.leftFocus.cy()
    const cyRight = this.props.rightFocus.cy()
    cyLeft.highlight(cyLeft.nodes(`#${idLeft}, [mergedIds*='#${idLeft}#']`))
    cyRight.highlight(cyRight.nodes(`#${idRight}, [mergedIds*='#${idRight}#']`))
  }

  dimAll() {
    this.props.leftFocus.cy().dim()
    this.props.rightFocus.cy().dim()
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

