export const Status = Object.freeze({
  unloaded: Symbol("unloaded"),
  idle: Symbol("idle"),
  rendering: Symbol("rendering")
})

export const Tidiness = Object.freeze({
  untidy: Symbol("untidy"),
  tidy: Symbol("tidy"),
  veryTidy: Symbol("very-tidy")
})

export const View = Object.freeze({
  plain: Symbol("plain"),
  cfg: Symbol("cfg")
})
