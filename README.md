# Cricket
Cricket is a project to act as a distributed harness for AFL, managing it
across a network.

# Status
The interface for Fuzzer and FuzzerView is complete, though there will likely
be a Harness struct that acts as an HTTP interface to the Fuzzer.

The Master is able to:
* Save, load network configurations
* Create a Network representation
* Get stats on individual FuzzViews

In Progress:
* Controlling data flow through FuzzerView and Network structs
* Proper fitness function for AFLView
* Harness to wrap the REST API in 'worker' into a trait

Future:
* Reproduction capabilities for Network and FuzzerView
* Prediction based breeding / Supervised ML

# Documentation

Documentation will be provided as the project stabilizes.
