# Cricket
Cricket is a project to act as a distributed fuzzing harness, managing them
across a network. Currently AFL (http://lcamtuf.coredump.cx/afl/) is supported.

AFL is wrapped in a Fuzzer trait, so any other fuzzer that implements the trait
will be compatible, allowing for different types of fuzzing to occur.

Cricket supports complex, graph-based, network structures. This allows for
simple programmatic manipulation of the network structure.

# Status
Current:
* Can load, save Network configurations.
* Can command AFLFuzzer instances to send/receive fuzzer_stats, queue data
* Can launch AFLFuzzer instances with custom arguments - more ergonomic support
  to come later.

In Progress:
* Automating data flow through FuzzerView and Network structs
* Proper fitness function for AFLView and Network structs
* Harness to wrap the REST API in 'worker' into a trait
* Score trait to assist in more complex fitness functions

Future:
* Reproduction capabilities for Network and FuzzerView
* Prediction based breeding / Supervised ML

# Documentation

Documentation will be provided as the project stabilizes.
