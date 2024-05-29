export function constraintsEq(c1, c2) {
  if (c1.length != c2.length) return false;
  for (let i = 0; i < c1.length; i++) {
    if (c1[i] != c2[i]) return false;
  }
  return true;
}
