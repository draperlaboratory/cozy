import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import Colors from "../data/colors.js"

class NodeBadge extends Component {

  badgeStyle(color) {
    return {
      background: color,
      color: "white",
      fontWeight: "bold",
      padding: "5px 10px 3px 10px",
      //less padding at the bottom because there's already naturally some space there for descenders.
      borderRadius: "25px",
      printColorAdjust: "exact"
    }
  }

  render(props) {
    const node = props.node
    if (node.data("error")) {
      return html`<span style=${this.badgeStyle(Colors.focusedErrorNode)}>Error:</span>`
    } else if (node.data("assertion_info")) {
      return html`<span style=${this.badgeStyle(Colors.focusedAssertNode)}>Assertion:</span>`
    } else if (node.data("postcondition_info")) {
      return html`<span style=${this.badgeStyle(Colors.focusedPostconditionNode)}>Postcondition:</span>`
    } else if (node.data("spinning")) {
      return html`<span style=${this.badgeStyle(Colors.focusedErrorNode)}>Error:</span>`
    }
  }
}

class BranchData extends Component {

  getData() {
    return this.props.node.data("error") ||
      this.props.node.data("assertion_info") ||
      this.props.node.data("postcondition_info") ||
      (this.props.node.data("spinning") && "Loop bounds exceeded") ||
      null
  }

  render(props) {
    const data = this.getData()
    if (!data) return

    return html`<div class="branch-data">
      <${NodeBadge} node=${props.node}/> ${data}
      </div>`
  }
}

class ReportField extends Component {
  onMouseEnter() {
    this.props.panel.cy.dim()
    this.props.panel.cy.highlight(this.props.leaf)
  }

  onMouseLeave() {
    this.props.panel.cy.dim()
  }

  onCheck(e) {
    const cy = this.props.panel.cy
    // pasing the ID rather than the node is necessary, since the graph may have
    // been regenerated, and the leaf attached to the report may no longer be
    // attached to the cytoscape graph
    if (e.target.checked) {
      this.props.setStatus("complete")
      cy.addCheckMark(this.props.leaf.id())
    } else {
      this.props.setStatus(undefined)
      cy.removeCheckMark(this.props.leaf.id())
    }
    this.props.refreshPrune()
  }

  onClick() {
    this.props.focus()
  }

  render(props) {
    const num = props.index + 1
    return html`<div class="report-field">
      <h2 
        onMouseEnter=${() => this.onMouseEnter()}
        onMouseLeave=${() => this.onMouseLeave()}
        onClick=${() => this.onClick()}
      >
        Path ${num}
      </h2>
      <${BranchData} node=${props.leaf}/>
      <form>
        <div>
        <textarea></textarea>
        </div>
        <div>
        <label for="reviewed-check">Review Complete</label>
        <input type="checkbox" onchange=${e => this.onCheck(e)} name="reviewed-check"></input>
        </div>
      </form>
    </div>`
  }
}

class ReportStatus extends Component {
  render(props) {
    return html`<div id="report-status">
        <h3>Review Coverage: ${Math.floor(props.value * 100 / props.max)}%</h3>
        <progress value=${props.value} max=${props.max}></progress>
      </div>`
  }
}

class ReportContents extends Component {
  differenceBullets() {
    const bullets = []
    const pruningStatus = this.props.pruningStatus
    if (pruningStatus.pruningMemory) {
      bullets.push(html`<li> differ with respect to final memory contents </li>`)
    }
    if (pruningStatus.pruningStdout) {
      bullets.push(html`<li> differ with respect to stdout behavior </li>`)
    }
    if (pruningStatus.pruningRegisters) {
      bullets.push(html`<li> differ with respect to final register contents</li>`)
    }
    if (pruningStatus.pruningEquivConstraints) {
      bullets.push(html`<li> differ with respect to final constraints</li>`)
    }
    if (pruningStatus.pruningCorrect) {
      bullets.push(html`<li> have an error, or correspond to an erroring branch </li>`)
    }
    if (pruningStatus.pruningDoRegex) {
      bullets.push(html`<li> don't match the regex <code>${pruningStatus.pruningRegex}</code>, 
        or correspond to a branch that doesn't match this regex </li>`)
    }
    return bullets
  }

  render(props) {
    const bullets = this.differenceBullets()
    return html`
      <h3>Summary:</h3>
      <p>Comparing 
        <code> ${props.prelabel} </code>
        and
        <code> ${props.postlabel}</code>.
      </p>
      ${bullets.length > 0 && 
          html`<p> Limiting attention to branches that: <ul>${bullets}</ul></p>`
      }`
  }
}

export default class Report extends Component {

  constructor(props) {
    super()
    this.state = {
      branchStatuses: {},
    }
    const panel = props.data.leftPanelRef
    this.leaves = [...panel.cy.nodes().leaves()]
  }

  componentDidMount() {
    const reportStyle = this.props.window.document.createElement("link")
    reportStyle.setAttribute("rel", "stylesheet")
    const loc = window.location
    reportStyle.setAttribute("href", `${loc.origin}${loc.pathname}/report.css`)
    this.props.window.document.head.appendChild(reportStyle)
  }

  getReportFields() {
    const panel = this.props.data.leftPanelRef
    return this.leaves.map((leaf, idx) => {
      return html`<${ReportField}
        setStatus=${(status) => this.setBranchStatus(idx, status)}
        leaf=${leaf}
        focus=${() => this.props.data.focusLeafById(leaf.id())}
        panel=${panel}
        refreshPrune=${this.props.data.refreshPrune}
        index=${idx}/>`
    })
  }

  setBranchStatus(idx, status) {
    this.setState(oldState => ({ branchStatuses: { ...oldState.branchStatuses, [idx]: status } }))
  }

  getProgress() {
    return Object
      .values(this.state.branchStatuses)
      .filter((status) => status == "complete")
      .length
  }

  render(props) {
    const fields = this.getReportFields()
    const progress = this.getProgress()
    return html`<main>
        <article>
          <h1 title="report-title">Cozy Report</h1>
          <div id="summary">
            <${ReportContents}
              prelabel=${props.data.prelabel}
              postlabel=${props.data.postlabel} 
              pruningStatus=${props.data.pruningStatus}
            />
            <${ReportStatus} value=${progress} max=${fields.length} />
          </div>
          ${fields}
        </article>
      </main>`
  }
}

