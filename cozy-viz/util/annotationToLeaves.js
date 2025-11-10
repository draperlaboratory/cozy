// Converts an annotation object into a array of annotation leaves, each consisting of
// a "path" to leaf, a pair of constraints associated with the leaf, and a tag
// indicating whether the leaf is an equality or inequality.

function isLeaf(annotation) {
  return typeof annotation === "object" &&
    Object.values(annotation).every(v => typeof v === "string") &&
    "tag" in annotation &&
    "left" in annotation &&
    "right" in annotation
}

export function annotationToLeaves(annotation, path = "root") {
  if (isLeaf(annotation)) {
    return [{...annotation, path}]
  }
  return Object.entries(annotation)
    .flatMap(([k,v]) => annotationToLeaves(v,`${path}.${k}`));
}
