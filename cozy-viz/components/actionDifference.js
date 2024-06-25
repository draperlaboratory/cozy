import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { getEdgesFromEnds } from '../util/segmentation.js'
import { hunkFormat } from './hunk.js'
import LineDiffView from './lineDiffView.js'
import SearchInput from './searchInput.js'

export default class ActionDifference extends Component {
  getActions(focus) {
    const segment = getEdgesFromEnds(focus.top, focus.bot).reverse()
    let contents = ""
    let msg = ""
    const lines = []
    const ids = []
    const msgs = []

    for (const edge of segment) {
      const id = edge.id()
      for (const line of edge.data('actions')) {
        contents += line + '\n'
        lines.push(line)
        msgs.push(msg)
        ids.push(id)
      }
    }

    if (focus.bot.data('actions')) {
      for (const line of focus.bot.data('actions')) {
        contents += line + '\n'
        lines.push(line)
        msgs.push(msg)
        ids.push("bottomNode")
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
    const cyLeft = this.props.leftFocus.cy()
    const cyRight = this.props.rightFocus.cy()
    if (idLeft == 'bottomNode') {
      const botId = this.props.leftFocus.bot.id()
      cyLeft.highlight(cyLeft.nodes(`#${botId}, [mergedIds*='#${botId}#']`))
    } else {
      const leftEdges = cyLeft.edges(`#${idLeft}, [mergedIds*='#${idLeft}#']`)
      cyLeft.highlight(leftEdges.sources())
    }
    if (idRight == 'bottomNode') {
      const botId = this.props.rightFocus.bot.id()
      cyRight.highlight(cyRight.nodes(`#${botId}, [mergedIds*='#${botId}#']`))
    } else {
      const rightEdges = cyRight.edges(`#${idRight}, [mergedIds*='#${idRight}#']`)
      cyRight.highlight(rightEdges.sources())
    }
  }

  dimAll() {
    this.props.leftFocus.cy().dim()
    this.props.rightFocus.cy().dim()
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
