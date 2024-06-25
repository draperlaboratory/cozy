import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { View } from '../data/cozy-data.js'
import { breadthFirst, cola, cose } from '../data/layouts.js'
import Menu from './menu.js'

export default class LayoutMenu extends Component {

  render(props) {
    return html`
      <${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Layout"
        setOpen=${o => props.setOpen(o)}>
        <${Menu.Option} 
          onClick=${() => props.resetLayout(breadthFirst, View.plain)}
          selected=${props.layout.name == "breadthfirst" && props.view == View.plain}>
            Tree
        <//>
        <${Menu.Option} 
          onClick=${() => props.resetLayout(breadthFirst, View.cfg)}
          selected=${props.layout.name == "breadthfirst" && props.view == View.cfg}>
            CFG - Tree layout
        <//>
        <${Menu.Option} onClick=${() => props.resetLayout()}
          onClick=${() => props.resetLayout(cose, View.cfg)}
          selected=${props.layout.name == "cose" && props.view == View.cfg}>
            CFG - Cose layout
        <//>
        <${Menu.Option} 
          onClick=${() => props.resetLayout(cola, View.cfg)}
          selected=${props.layout.name == "cola" && props.view == View.cfg}>
            CFG - Cola layout
        <//>
        <${Menu.Option} onClick=${() => props.resetLayout()}>
            Refresh
        <//>
      <//>`
  }
}
