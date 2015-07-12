# Cricket
Cricket is a project to act as a distributed fuzzing harness, managing them
across a network. Currently AFL (http://lcamtuf.coredump.cx/afl/) is supported.

AFL is wrapped in a Fuzzer trait, so any other fuzzer that implements the trait
will be compatible, allowing for different types of fuzzing to interact.

Cricket supports complex, graph-based network structures. This allows for
simple programmatic manipulation of the network structure.

# Status
As the 'example.rs' and 'stable.rs' files will demonstrate Cricket provides
enough capabilities to handle basic distributed fuzzing. One can create their
network structure, command the fuzzers to begin work, and repeatedly collect
stats on the fuzzers success.

# Documentation
Rustdoc documentation will be provided when the project stabilizes. The majority
of the code is currently documented.
