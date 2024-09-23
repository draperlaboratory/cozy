import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import ConcretionSelector from './concretionSelector.js'
import LineDiffView from './lineDiffView.js'
import * as Diff from 'https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm'

export default class SideEffectDifference extends Component {
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

  handleSymbolicDiff(symbolicDiff) {
    const rslt = {}
    for (const channel in symbolicDiff) {
      const lines = {}
      lines.left = symbolicDiff[channel].map(([x,]) => ({ body: x }))
      lines.right = symbolicDiff[channel].map(([, x]) => ({ body: x }))
      rslt[channel] = lines
    }
    return rslt
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
    const symbolicDiff = props.leftFocus.bot.data().compatibilities[rightId].sediff ?? {}
    const chandivs = []
    const replacer = (_, s) => s == "leafNeq" ? "These constraints are not equivalent"
      : s == "fieldEq" ? "The remaining constrants shown here are equivalent"
        : s
    if (state.view == "symbolic") {
      for (const channel in symbolicDiff) {
        const chandiv = html`<div class="side-effect-channel">
          <h3>${channel}</h3>
          ${symbolicDiff[channel].map(([, , x]) => html`<pre>${JSON.stringify(x, replacer, 2)}</pre>`)}
        </div>`
        chandivs.push(chandiv)
      }
    } else {

      // Note, line-diffing is handled on the python side, because of the
      // complexity of diffing non-concrete side effects. Hence, we have
      // a trivial comparator here.
      const sediffs = concretions[state.view]
      for (const channel in sediffs) {
        if (!(channel in symbolicDiff)) continue
        const chandiv = html`<div class="side-effect-channel">
          <h3>${channel}</h3>
          <${LineDiffView} 
            leftLines=${this.diffableSideEffects(
          sediffs[channel].left,
          symbolicDiff[channel].map(([x,]) => x)
        )}
            rightLines=${this.diffableSideEffects(
          sediffs[channel].right,
          symbolicDiff[channel].map(([, y]) => y)
        )}
            diffWords=${(l, r) => this.diffWords(l, r)}
            comparator=${() => true}
            highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
            dim=${() => this.dimAll()}
          />
        </div>`
        chandivs.push(chandiv)
      }
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
