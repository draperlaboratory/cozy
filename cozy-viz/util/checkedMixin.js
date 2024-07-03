export const checkedMixin = {

  checkedIds: new Set(),

  setCheckMarks(nodes) {
    this.nodes().removeData("checked")
    this.checkedIds = new Set([...nodes.map(node => node.id())])
    nodes.data("checked", true)
  },

  addCheckMark(id) {
    this.checkedIds.add(id)
    this.nodes(`#${id}`).data("checked", true)
  },

  removeCheckMark(id) {
    this.checkedIds.delete(id)
    this.nodes(`#${id}`).data("checked", false) //needed to force the cytoscape view to update
    this.nodes(`#${id}`).removeData("checked")
  },

  restoreCheckMarks() {
    this.setCheckMarks(this.filter(node => this.checkedIds.has(node.id())))
  }
}
