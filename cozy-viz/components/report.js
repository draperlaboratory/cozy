import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'

export default class Report extends Component {
  constructor() {
    super()
  }

  componentWillMount() {
    const reportStyle = this.props.window.document.createElement("link")
    reportStyle.setAttribute("rel","stylesheet")
    const loc = window.location
    reportStyle.setAttribute("href",`${loc.origin}${loc.pathname}/report.css`)
    this.props.window.document.head.appendChild(reportStyle)
  }

  render() {
    return html`<main>
        <article>
          <h1 title="report-title">Cozy Report</h1>
        </article>
      </main>`
  }
}
