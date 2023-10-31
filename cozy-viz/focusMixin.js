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

  refocus() {
    this.elements()
      .removeClass('pathHighlight')
      .removeClass('availablePath');
    this.focus(this.loci)

    return this
  },

  blur() {
    this.loci = null

    this.elements()
      .removeClass('pathHighlight')
      .removeClass('availablePath');

    return this
  }
}

