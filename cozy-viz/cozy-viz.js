import App from './components/app.js'
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { render } from 'https://unpkg.com/preact@latest?module'

render(html`<${App}/>`, document.body);
