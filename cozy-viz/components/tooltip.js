import { computePosition, flip } from 'https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm';
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'

export default class Tooltip extends Component {
  constructor() {
    super();
    this.state = {
      style : {
        visibility:"hidden",
        left: 0,
        top: 0,
        zIndex: 0,
      },
      mode : null
    }
  }

  attachTo(cyNode) {
    this.setState({node : cyNode}, () => this.refreshPosition());
  }

  refreshPosition() {
    const {x, y} = this.state.node
      .cy().container().getBoundingClientRect()

    const tooltip = this.base;

    const theNode = this.state.node

    const virtualElt = {
      getBoundingClientRect() {
        const bbox = theNode.renderedBoundingBox();
        return { 
          x: bbox.x1 + x, 
          y: bbox.y1 + y, 
          top: bbox.y1 + y,
          left: bbox.x1 + x, 
          bottom: bbox.y2 + y, 
          right: bbox.x2 + x, 
          height: bbox.h, 
          width: bbox.w
        }
      }
    };

    computePosition(virtualElt, tooltip, { 
      placement: "right-end",
      middleware: [flip()]
    }).then(({x,y, placement}) => 
      this.positionAt(x,y, placement)
    )
  }

  positionAt(x,y, placement) {
    this.setState({
      style : {
        flexDirection: placement.slice(-3) == "end" 
          ? "column-reverse"
          : "column"
        ,
        visibility:"visible",
        left: `${x}px`,
        top: `${y}px`,
        zIndex: 5,
    }})
  }

  getViewData() {
    switch (this.state.mode) {
      case "constraints" : { 
        return html`<pre>${
            this.state.node?.data().constraints?.map?.(
              c => html`<div>${c}</div>`
            )}</pre>`
      }
      case "assembly" : { 
        return html`<pre>${this.state.node.data().contents}</pre>`
      }
      case "vex" : { 
        return html`<pre>${this.state.node.data().vex}</pre>`
      }
      case "errors" : { 
        if (this.state.node.data().error) {
          return html`<pre>${this.state.node.data().error}</pre>`
        } else if (this.state.node.data().spinning) {
          return html`<pre>Spinning: Loop bounds exceeded</pre>`
        } else {
          return null
        }
      }
      case "stdout" : { 
        if (this.state.node.data().stdout) {
          return html`<pre>${this.state.node.data().stdout}</pre>`
        } else {
          return null
        }
      }
      case "stderr" : { 
        if (this.state.node.data().stderr) {
          return html`<pre>${this.state.node.data().stderr}</pre>`
        } else {
          return null
        }
      }
      case "simprocs" : { 
        return html`<pre>${
          this.state.node?.data().simprocs?.map?.(
            simproc => html`<div>${simproc}</div>`
          )}</pre>`
      }
      case "assertion" : {
        if (this.state.node?.data().assertion_info) {
          return html`
          <div>${this.state.node?.data().assertion_info}</div>
          <pre>
          Condition: ${this.state.node?.data().failed_cond}<br/>
          Address: ${this.state.node?.data().assertion_addr}
          </pre>
          `
        } else {
          return null
        }
      }
      case "postcondition" : {
        if (this.state.node?.data().postcondition_info) {
          return html`
          <div>${this.state.node?.data().postcondition_info}</div>
          <pre>
          Condition: ${this.state.node?.data().failed_cond}<br/>
          </pre>
          `
        } else {
          return null
        }
      }
      default: return null;
    }
  }

  setView(mode) {
    this.setState({mode}, () => this.refreshPosition())
  }

  clearTooltip() {
    this.setState({style : {
      visibility:"hidden",
      left: 0,
      top: 0,
      zIndex: 0,
    }})
  }

  render(_props,state) {
    return html`<div id="tooltip" style=${state.style}>
      <div id="tooltip-buttons">
        <button
          data-highlighted=${state.mode == "assembly"} 
          onClick=${() => this.setView("assembly")}>
          Assembly
        </button>
        ${this.state.node?.data().constraints && html`
          <button
            data-highlighted=${state.mode == "constraints"} 
            onClick=${() => this.setView("constraints")}>
            Constraints
          </button>`
        }
        ${this.state.node?.data().vex && html`
          <button 
            data-highlighted=${state.mode == "vex"} 
            onClick=${() => this.setView("vex")}>
            Vex IR
          </button>`
        }
        ${(this.state.node?.data().error ||
          this.state.node?.data().spinning) && html`
          <button 
            data-highlighted=${state.mode == "errors"} 
            onClick=${() => this.setView("errors")}>
            Errors
          </button>`
        }
        ${this.state.node?.data().stdout && html`
          <button 
            data-highlighted=${state.mode == "stdout"} 
            onClick=${() => this.setView("stdout")}>
            Stdout
          </button>`
        }
        ${this.state.node?.data().stderr && html`
          <button 
            data-highlighted=${state.mode == "stderr"} 
            onClick=${() => this.setView("stderr")}>
            Stderr
          </button>`
        }
        ${this.state.node?.data().simprocs?.length > 0 && html`
          <button 
            data-highlighted=${state.mode == "simprocs"} 
            onClick=${() => this.setView("simprocs")}>
            SimProcedures
          </button>`
        }
        ${this.state.node?.data().assertion_info && html`
          <button 
            data-highlighted=${state.mode == "assertion"} 
            onClick=${() => this.setView("assertion")}>
            Assertion
          </button>`
        }
        ${this.state.node?.data().postcondition_info && html`
          <button 
            data-highlighted=${state.mode == "postcondition"} 
            onClick=${() => this.setView("postcondition")}>
            Postcondition
          </button>`
        }
      </div>
      <div id="tooltip-data">${this.getViewData()}</div>
    </div>`
  }
}
