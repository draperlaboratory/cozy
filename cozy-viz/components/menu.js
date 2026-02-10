import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component, createRef } from 'https://unpkg.com/preact@latest?module'
import { computePosition } from 'https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm';

// this should be mounted and unmounted rather than toggled; adding and removing
// the event-listener for closing the menu should be part of the mount/unmount
// lifecycle
export default class Menu extends Component {
  constructor() {
    super()
    this.button = createRef()
    this.options = createRef()
  }

  static Option = class extends Component {
    render(props) {
      return html`<div class="option"
        data-selected=${props.selected} 
        data-disabled=${props.disabled}
        onClick=${props.disabled ? null : props.onClick}>
            ${props.children}
      </div>`
    }
  }

  componentDidUpdate() {
    if (this.props.open == this.props.title) {
      computePosition(this.button.current, this.options.current, {
        placement: "bottom-start"
      }).then(({ x, y }) => {
        this.options.current.style.left = `${x}px`
        this.options.current.style.top = `${y}px`
      })
    }
  }

  toggleOpen() {
    if (!this.props.enabled) return
    if (this.props.open != this.props.title) {
      this.props.setOpen(this.props.title)
    } else {
      this.props.setOpen(null)
    }
  }

  render(props) {
    const optionStyle = {
      position: "absolute",
      display: "block",
      backgroundColor: "#e1e1e1"
    }
    const menuStyle = {
      color: props.enabled ? "black" : "#ccc",
      backgroundColor: props.open === props.title
        ? "#e1e1e1"
        : "white"
    }
    return html`
      <button 
        style=${menuStyle} 
        ref=${this.button} 
        onClick=${() => this.toggleOpen()}
        onMouseEnter=${() => props.open && this.props.enabled && props.setOpen(props.title)}>
        ${props.title}
      </button>
      ${props.open == props.title && html`
        <div style=${optionStyle} ref=${this.options} class="options-wrapper">
          ${props.children}
        </div>`
      }`
  }
}

