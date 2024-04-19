# Injection Attack Demo

## Build Instructions

run `make`.

## Usage

`injectionAttack` takes three parameters on the command line, `command`,
`role`, and `data`. `command` must be either `DELETE` or `STORE`, and
`role` must be either `root` or `guest`. `data` can be anything.
`root` can perform any command, but `guest` may only store and cannot `DELETE`.

Internally, parameters are serialized as `c:$command;r:$role;d:$data` and then
deserialized. This creates a vulnerability, since if `guest` issues the command
`DELETE;r:root;d:`, the result will be serialized and then de-serialized in a way
that carries out the `DELETE` even though role is `guest`.

## Patches

`injectionAttack-badPatch` tries to fix the vulnerability by checking if there
are more than two semicolons in the serialized data. This is bad, because it
prevents `$DATA` from containing semicolons.

`injectionAttack-goodPatch` tries to fix the vulnerability by prohibiting
semicolons in `$COMMAND`. This hopefully fixes the vulnerability.
