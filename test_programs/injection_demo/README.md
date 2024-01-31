# Injection Attack Demo

## Build Instructions

run `make`.

## Usage

`injectionAttack` takes three parameters on the command line, `$COMMAND`,
`$ROLE`, `$DATA`. `$COMMAND` is intended to be either `DELETE` or `STORE`, and
`$ROLE` is intended to be either `root` or `guest`. `$DATA` can be anything.
`root` can perform any command, but `guest` may not `DELETE`.

Internally, parameters are serialized as `c:$COMMAND;r:$ROLE;d:$DATA` and then
deserialized. This creates a vulnerability, since if `guest` issues the command
`DELETE;r:root;d:`, the result will be serialize and then de-serialize in a way
that carries out the `DELETE`.

## Patches

`injectionAttack-badPatch` tries to fix the vulnerability by checking if there
are more than two semicolons in the serialized data. This is bad, because it
prevents `$DATA` from containing semicolons.

`injectionAttack-goodPatch` tries to fix the vulnerability by prohibiting
semicolons in `$COMMAND`. This hopefully fixes the vulnerability.
