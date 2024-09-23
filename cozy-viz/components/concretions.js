import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'

export default class Concretions extends Component {

  constructor() {
    super()
    this.state = {
      view: "shared"
    }
  }

  render(props, state) {
    const rightId = props.rightFocus.bot.id()
    const leftId = props.leftFocus.bot.id()
    const examples = []
    const sharedConcretions = props.leftFocus.bot.data().compatibilities[rightId].conc_args
    const leftOnlyConcretions = Object.entries(props.leftFocus.bot.data().compatibilities).flatMap(
      ([key, compat]) => key == rightId ? [] : compat.conc_args
    )
    const rightOnlyConcretions = Object.entries(props.rightFocus.bot.data().compatibilities).flatMap(
      ([key, compat]) => key == leftId ? [] : compat.conc_args
    )

    const concretions =
      state.view == "shared" ? sharedConcretions
        : state.view == "left" ? leftOnlyConcretions
          : state.view == "right" ? rightOnlyConcretions
            : null

    for (const concretion of concretions) {
      examples.push(html`
        <pre class="concrete-example">${JSON.stringify(concretion, undefined, 2)}</pre>
      `)
    }

    const sharedMsg = sharedConcretions.length == 0
      ? "No concretions available"
      : html`Viewing ${sharedConcretions.length} concrete input examples shared by both branches`

    const leftMsg = leftOnlyConcretions.length == 0
      ? rightOnlyConcretions.length == 0
        ? "There are no inputs that go down the left but not the right branch. The two branches correspond to exactly the same inputs."
        : "There are no inputs that go down the left but not the right branch. The left branch refines the right."
      : html`Viewing ${leftOnlyConcretions.length} concrete input examples that go down the left but not the right branch`

    const rightMsg = rightOnlyConcretions.length == 0
      ? leftOnlyConcretions.length == 0
        ? "There are no inputs that go down the right but not the left branch. The two branches correspond to exactly the same inputs."
        : "There are no inputs that go down the right but not the left branch. The right branch refines the left."
      : html`Viewing ${rightOnlyConcretions.length} concrete input examples that go down the right but not the left branch`

    return html`
    <div class="subordinate-buttons">
      <button
        data-selected=${state.view == "shared"}
        onClick=${() => this.setState({ view: "shared" })}
      >Shared</button>
      <button
        data-selected=${state.view == "left"}
        onClick=${() => this.setState({ view: "left" })}
      >Left Branch Only</button>
      <button
        data-selected=${state.view == "right"}
        onClick=${() => this.setState({ view: "right" })}
      >Right Branch Only</button>
    </div>
    <div id="concretion-header">
      ${state.view == "shared" ? sharedMsg
        : state.view == "left" ? leftMsg
          : state.view == "right" ? rightMsg
            : null
      }
    </div>
    <div id="concretion-data">
      ${examples}
    </div>`
  }
}
