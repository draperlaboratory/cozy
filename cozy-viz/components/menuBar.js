import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { render } from 'https://unpkg.com/preact@latest?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { Status } from '../data/cozy-data.js'
import Report from './report.js'
import Menu from './menu.js'
import SearchMenu from './searchMenu.js'
import PruneMenu from './pruneMenu.js'
import ViewMenu from './viewMenu.js'
import LayoutMenu from './layoutMenu.js'
import { View } from '../data/cozy-data.js'

export default class MenuBar extends Component {
  constructor() {
    super()
    this.state = {
      open: null,
      searchStdoutRegex: ".*",
    }
  }

  componentDidMount() {
    this.globalClickListener = ev => this.handleGlobalClick(ev)
    this.closeListener = () => this.setOpen(null)
    window.addEventListener("blur", this.closeListener)
    window.addEventListener("mousedown", this.globalClickListener)
  }

  componentWillUnmount() {
    window.removeEventListener("blur", this.closeListener)
    window.removeEventListener("mousedown", this.globalClickListener)
  }

  setOpen(open) {
    this.setState({ open })
  }

  handleGlobalClick() {
    if (this.state.open) {
      this.setState({ open: null })
    }
  }

  handleLocalClick(ev) {
    if (this.state.open) {
      ev.stopPropagation()
    }
  }

  resetLayout(layout, view) {
    this.props.resetLayout(layout, view)
    this.setOpen(null)
  }

  saveFile(data) {
    const filename = prompt("please provide a filename")

    var blob = new Blob([data], { type: 'text/json' }),
      a = document.createElement('a')

    a.download = filename
    a.href = window.URL.createObjectURL(blob)
    a.dataset.downloadurl = ['text/json', a.download, a.href].join(':')
    a.dispatchEvent(new MouseEvent("click"))
  }

  openReport() {
    this.reportWindow = open()
    if (!this.reportWindow) {
      alert("couldn't open report - double check that cozy has permission to open new windows in your popup-blocker")
    }
    render(html`<${Report} 
      data=${this.props.getReportInterface()} 
      window=${this.reportWindow}/>`,
      this.reportWindow.document.body)
  }

  render(props, state) {
    const enabled = props.status === Status.idle
    return html`<div id="menubar"
        onMousedown=${ev => this.handleLocalClick(ev)}
      >
      <${Menu} 
        enabled=${enabled}
        open=${state.open}
        title="Files"
        setOpen=${o => this.setOpen(o)}>
        <${Menu.Option} onClick=${() => this.saveFile(props.getJSON())}>
          Save Graph
        <//>
        <${Menu.Option} disabled=${props.view != View.plain} onClick=${() => this.openReport()}>
          Open New Report
        <//>
      <//>
      <${ViewMenu}
        ref=${props.viewMenu}
        enabled=${enabled && props.view == View.plain} 
        tidiness=${props.tidiness}
        pruneMenu=${props.pruneMenu}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
        open=${state.open}
        regenerateFocus=${props.regenerateFocus}
        refreshLayout=${props.refreshLayout}
        batch=${props.batch}
        setOpen=${o => this.setOpen(o)}
      />
      <${PruneMenu} 
        ref=${props.pruneMenu}
        enabled=${enabled && props.view == View.plain} 
        viewMenu=${props.viewMenu}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
        refreshLayout=${props.refreshLayout}
        open=${state.open}
        setOpen=${o => this.setOpen(o)}
      />
      <${LayoutMenu}
        open=${state.open}
        enabled=${enabled}
        setOpen=${o => this.setOpen(o)}
        layout=${props.layout}
        view=${props.view}
        resetLayout=${(o,v) => this.resetLayout(o,v)}
      />
      <${SearchMenu}
        enabled=${enabled}
        open=${state.open}
        setOpen=${o => this.setOpen(o)}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
      />
    </div>`
  }
}
