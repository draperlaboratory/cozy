export function closeGhidraServer() {
  // we used XMLHttpRequest because this needs to be done
  // synchronously, beforeunload doesn't block for async functions to
  // finish.
  const req = new XMLHttpRequest
  req.open("DELETE", '/', false)
  req.send()
}

export function gotoAddrInGhidra(addr) {
  addr = addr.trim()
  fetch('/', {
    method: "POST",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify({ addr })
  })
}
