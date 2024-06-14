import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'


class ReportField extends Component {
  onMouseEnter(e) {
    this.props.panel.cy.dim()
    this.props.panel.cy.highlight(this.props.leaf)
  }

  onCheck(e) {
    if (e.target.checked) {
      this.props.setStatus("complete")
    } else {
      this.props.setStatus(undefined)
    }
  }

  onClick() {
    this.props.focus()
  }

  render(props) {
    const num = props.index + 1
    return html`<div class="report-field">
      <h2 
        onMouseEnter=${e => this.onMouseEnter(e)}
        onClick=${() => this.onClick()}
      >
        Path ${num}
      </h2>
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

export default class Report extends Component {

  constructor() {
    super()
    this.state = {
      branchStatuses: {},
    }
  }

  componentWillMount() {
    const reportStyle = this.props.window.document.createElement("link")
    reportStyle.setAttribute("rel","stylesheet")
    const loc = window.location
    reportStyle.setAttribute("href",`${loc.origin}${loc.pathname}/report.css`)
    this.props.window.document.head.appendChild(reportStyle)
  }

  getReportFields() {
    const panel = this.props.data.leftPanelRef
    return panel.cy.nodes().leaves().map((leaf,idx) => {
      return html`<${ReportField}
        setStatus=${(status) => this.setBranchStatus(idx,status)}
        leaf=${leaf}
        focus=${() => this.props.data.focusLeaf(leaf)}
        panel=${panel}
        index=${idx}/>`
    })
  }

  setBranchStatus(idx, status)  {
    this.setState(oldState => ({branchStatuses: { ...oldState.branchStatuses, [idx]: status }}))
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
            <h3>Summary:</h3>
            <p>Comparing 
              <code> ${props.data.prelabel} </code>
              and
              <code> ${props.data.postlabel}</code>.
            </p>
            <${ReportStatus} value=${progress} max=${fields.length}/>
          </div>
          ${fields}
        </article>
      </main>`
  }
}

