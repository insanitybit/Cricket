# Cricket

[![Build Status](https://travis-ci.org/insanitybit/Cricket.png)](https://travis-ci.org/insanitybit/Cricket)

Cricket is a project to act as a distributed fuzzing harness, managing fuzzers
across a network. Currently AFL (http://lcamtuf.coredump.cx/afl/) is supported.

AFL is wrapped in a Fuzzer trait, so any other fuzzer that implements the trait
will be compatible, allowing for different types of fuzzers to interact and share
their corpora.

Cricket provides a struct, Network, that can manage 'views' of the fuzzers
across a network.

# Status
As the 'master.rs' and 'worker.rs' files will demonstrate, Cricket provides
enough capabilities to handle basic distributed fuzzing. One can create their
network structure, command the fuzzers to begin work, and repeatedly collect
stats on the fuzzers success. I've tested this on ec2 instances myself, and
it worked quite well.

See issues for future development.

# Documentation
Rustdoc documentation coming.
