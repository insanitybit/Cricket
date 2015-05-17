# Cricket
Cricket is a NodeJS harness for the American Fuzzy Lopper (AFL) fuzzer:
lcamtuf.coredump.cx/afl/README.txt

AFL is a generic binary format fuzzer that uses binary (or QEMU) instrumentation
to track a target's code paths in order to gauge fuzzing progress.

Instances of Cricket can be deployed across servers, allowing AFL to take
advantage of multiple systems.

Each instance maintains its own forward list of 'workers' and it will pass its
queue to these periodically. This facilitates complex fuzzing structures.

One could make two separate circular linked lists of cricket nodes with a single
shared node in between them, leading to arbitrarily complex structures.

The goal of Cricket is to facilitate arbitrarily complex fuzzing structures to
observe their effect on AFL, and eventually to implement genetic algorithms that
take advantage of these structures.


Status:
--------

Incomplete, not ready for use.

Currently, Cricket is capable of:
* Registering worker nodes
* Passing /queue/ information across systems
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
