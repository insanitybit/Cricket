# Cricket
Cricket is a NodeJS harness for the American Fuzzy Lopper (AFL) fuzzer:
lcamtuf.coredump.cx/afl/README.txt

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

Status:
--------

Incomplete, not ready for use.

Currently, Cricket is capable of:
* Registering worker nodes
* Passing /queue/ information across systems periodically
* Fuzzing across networks

The above are the bare bones capabilities of Cricket, the future versions will
refine the above.

Future versions will also try to accomplish the following:
* Forward AFL output to terminal or canvas interface
* Provide graphic/ canvas interface for linking/ visualizing worker structure
* Provide further genetic mutation utilizing the information from full network
* Formalize an 'environment' concept for genetic mutation



Usage:
------
Instances of Cricket are either Master or Workers. The Master nodes are where
you interact with Cricket, but are otherwise functionally identical to the
Worker nodes.

Starting instances of Cricket is simple:

Master:
node ./cricket.js -M

Worker:
node ./cricket.js -W --mp=[master IP]

The worker has the optional --mp arg that signifies the Master's hostname. This
allows the worker to register with an already running Master.

Master's will otherwise get their worker hostnames through the config.ini in
/config/

config.ini:
This configuration file contains all of the path information for your AFL binary
as well as the sync directory, testcases, and target. Also where you set AFL and
target parameters.

pairs.json:
This file contains JSON describing the host pairs. The file contains an example
of what the JSON should look like.
