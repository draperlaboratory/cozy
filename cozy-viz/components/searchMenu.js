import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import Menu from './menu.js'

export default class SearchMenu extends Component {
  constructor() {
    super()
    this.state = {
      searchStdoutRegex: "",
    }
  }

  updateSearch(e) {
    if (e.target.value == '') this.clearSearch()
    else {
      this.setState({ searchStdoutRegex: e.target.value }, () => {
        const cyLeft = this.props.cyLeft.cy
        const cyRight = this.props.cyRight.cy
        cyLeft.dim()
        cyRight.dim()
        let regex
        try {
          regex = new RegExp(this.state.searchStdoutRegex)
        } catch (e) {
          return
        }
        const ltargets = cyLeft.nodes()
          .filter(node => node.data().stdout.match(regex))
        const rtargets = cyRight.nodes()
          .filter(node => node.data().stdout.match(regex))
        cyLeft.highlight(ltargets)
        cyRight.highlight(rtargets)
      })
    }
  }

  clearSearch() {
    this.setState({ searchStdoutRegex: '' }, () => {
      const cyLeft = this.props.cyLeft.cy
      const cyRight = this.props.cyRight.cy
      cyLeft.dim()
      cyRight.dim()
    })
    this.props.setOpen(null)
  }

  render(props, state) {
    return html`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Search"
        setOpen=${o => props.setOpen(o)}>
        <${Menu.Option} onClick=${() => props.setOpen(null)}>
          Stdout <input 
            placeholder=".*"
            onClick=${e => e.stopPropagation()}
            onInput=${e => this.updateSearch(e)} 
            value=${state.searchStdoutRegex}/>
        <//>
        <${Menu.Option} onClick=${() => this.clearSearch(null)}>
          Clear Search 
        <//>
      <//>`
  }
}
