import * as Diff from 'https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm'
import { html } from 'https://unpkg.com/htm/preact/index.module.js?module'
import { Component } from 'https://unpkg.com/preact@latest?module'
import { Hunk } from './hunk.js'

export default class LineDiffView extends Component {
  getContents() {
    if (!this.props.leftLines && !this.props.rightLines) return null
    if (!this.props.rightLines) {
      const {
        lines: leftLines,
        ids: leftIds,
        msgs: leftMsgs,
      } = this.props.leftLines
      const hunkCtx = { leftIds, rightIds: [""], leftMsgs, rightMsgs: [""] }
      return leftLines
        .map((line, idx) => Hunk({
          hunkCtx,
          curLeft: idx,
          curRight: 0,
          leftContent: this.props.format?.(line) || line,
          rightContent: " ",
        }))
    }
    if (!this.props.leftLines) {
      const {
        lines: rightLines,
        ids: rightIds,
        msgs: rightMsgs,
      } = this.props.rightLines
      const hunkCtx = { rightIds, leftIds: [""], rightMsgs, leftMsgs: [""] }
      return rightLines
        .map((line, idx) => Hunk({
          hunkCtx,
          curLeft: 0,
          curRight: idx,
          leftContent: " ",
          rightContent: this.props.format?.(line) || line,
        }))
    }
    return this.diffLines()
  }

  diffLines() {
    // simple memoization
    if (this.prevLeftLines == this.props.leftLines &&
      this.prevRightLines == this.props.rightLines) {
      return this.prevDiff
    }

    this.prevLeftFocus = this.props.leftFocus
    this.prevRightFocus = this.props.rightFocus

    const {
      contents: leftContents,
      lines: leftLines,
      ids: leftIds,
      msgs: leftMsgs,
    } = this.props.leftLines

    const {
      contents: rightContents,
      lines: rightLines,
      ids: rightIds,
      msgs: rightMsgs,
    } = this.props.rightLines

    const hunkCtx = { leftIds, leftMsgs, rightIds, rightMsgs }
    const diffs = Diff.diffLines(leftContents, rightContents, {
      comparator: this.props.comparator
    })
    let rendered = []
    let curLeft = 0
    let curRight = 0
    let mkHunk = ({ curLeft, curRight, leftContent, rightContent, leftClass, rightClass }) => Hunk({
      highlight: this.props.highlight
        ? () => this.props.highlight(leftIds[curLeft], rightIds[curRight])
        : () => { },
      dim: this.props.dim
        ? () => this.props.dim()
        : () => { },
      hunkCtx,
      curLeft,
      curRight,
      leftContent,
      rightContent,
      leftClass,
      rightClass,
    })

    for (const diff of diffs) {
      if (diff?.added) {
        for (const line of diff.value.split('\n')) {
          if (line == "") continue
          const hunk = mkHunk({
            curLeft,
            curRight,
            leftContent: " ",
            rightContent: this.props.format?.(line) || line,
            rightClass: "hunkAdded",
          })
          curRight++
          rendered.push(hunk)
        }
      } else if (diff?.removed) {
        for (const line of diff.value.split('\n')) {
          if (line == "") continue
          const hunk = mkHunk({
            curLeft,
            curRight,
            leftContent: this.props.format?.(line) || line,
            rightContent: " ",
            leftClass: "hunkRemoved",
          })
          curLeft++
          rendered.push(hunk)
        }
      } else {
        for (let i = 0; i < diff.count; i++) {
          let rightContent = this.props.format?.(rightLines[curRight]) || rightLines[curRight]
          let leftContent = this.props.format?.(leftLines[curLeft]) || leftLines[curLeft];
          [leftContent, rightContent] = this.props.diffWords?.(leftContent, rightContent) || [leftContent, rightContent]
          const hunk = mkHunk({
            curLeft,
            curRight,
            leftContent,
            rightContent,
          })
          curRight++
          curLeft++
          rendered.push(hunk)
        }
      }
    }

    this.prevDiff = rendered

    return rendered
  }

  render(props) {
    const hunks = this.getContents().filter(({ contentListing }) => {
      if (!props.filterExpr) return true
      let lineFilter
      try {
        lineFilter = new RegExp(props.filterExpr)
      } catch (e) {
        lineFilter = /^/
      }

      return lineFilter.test(contentListing.left) ||
        lineFilter.test(contentListing.right)
    })

    return html`<pre id="line-diff-data-view">${hunks}</pre>`
  }
}
