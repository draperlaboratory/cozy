export const focusMixin = {
  focus(loci) {
    if (!loci) return;

    this.loci = loci;

    for (const locus of loci) {
      if (locus.removed()) continue
      if (loci.length > 1) {
        locus.addClass('availablePath');
      } else {
        locus.addClass('pathHighlight');
      }

      locus
        .predecessors()
        .addClass('pathHighlight');
    }

    return this
  },

  // focus a range of nodes, and set its lower tips to be the loci
  focusRange(nodes) {

    this.elements().removeClass("pathHighlight")
    this.elements().removeClass("availablePath")

    this.loci = nodes.filter(
      ele => ele.outgoers("node").intersection(nodes).length == 0)

    nodes.addClass('pathHighlight')

    if (this.loci.length > 1) {
      for (const locus of this.loci) {
        locus.removeClass('pathHighlight');
        locus.addClass('availablePath');
      }
    } else {
      this.loci.addClass('pathHighlight');
    }
  },

  refocus() {
    this.elements()
      .removeClass('pathHighlight')
      .removeClass('availablePath');
    this.focus(this.loci)

    return this
  },

  highlight(nodes) {
    nodes.addClass('temporaryFocus')
  },

  dim() {
    this.elements().removeClass('temporaryFocus')
  },

  blur() {
    this.loci = null

    this.elements()
      .removeClass('pathHighlight')
      .removeClass('availablePath');

    return this
  }
}

