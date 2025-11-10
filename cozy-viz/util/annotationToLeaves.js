// Converts an annotation object into a array of annotation leaves, each consisting of
// a "path" to leaf, a pair of constraints associated with the leaf, and a tag
// indicating whether the leaf is an equality or inequality.

function isSymLeaf(annotation) {
  return typeof annotation === "object" &&
    Object.values(annotation).every(v => typeof v === "string") &&
    "tag" in annotation &&
    "left" in annotation &&
    "right" in annotation
}

export function symAnnotationToLeaves(annotation, path = "root") {
  if (isSymLeaf(annotation)) {
    return [{...annotation, path}]
  }
  return Object.entries(annotation)
    .flatMap(([k,v]) => symAnnotationToLeaves(v,`${path}.${k}`));
}

export function concAnnotationToLeaves({ left, right }, path = "root") {
  if (typeof left === "object" && typeof right === "object") {
    return Object.keys(left)
      .flatMap(k => concAnnotationToLeaves({left : left[k], right : right[k]}, `${path}.${k}`))
  } else {
    return { left, right, path }
  }
}
