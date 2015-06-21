# Cricket
Cricket is a harness for AFL, currently built in rust (see /old/ for NodeJS).

Cricket's purpose is to allow for servers running AFL to share information in
interesting ways. One example of this would be to have a network where each
server maintains a connection to the next, forming a circular linked list:

A -> B -> C -> A

This would allow AFL data to be waterfalled periodically.

More complex structures can also be formed, such as one where two lists exist:


A -> B -> C -> A

D -> E -> F -> A -> D

This would be two circular linked lists that share the single A node.

The structures can be arbitrarily complex.

Status: NodeJS version works, but future development will be on the Rust version.

The current version of Cricket lacks a 'Master', but the Worker is largely built.
