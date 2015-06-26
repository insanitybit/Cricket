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
* Controlling data flow through FuzzerView and Network structs.
* Proper fitness function for AFLView

Future:
* Reproduction capabilities for Network and FuzzerView
* Prediction based breeding / Supervised ML

# Information

There are three main components to Cricket, the Fuzzer, FuzzerView, and the
Network.

Fuzzer:

The Fuzzer trait provides an interface to an underlying fuzzer.

Cricket provides a web based interface to an AFLFuzzer, which implements the
Fuzzer trait. In the future it may support others - any fuzzer struct that
implements the Fuzzer trait will work with Cricket.

FuzzerView:

The FuzzerView trait provides an interface to a representation of a Fuzzer on
the network - it provides a similar interface to Fuzzer, but it deals with
remote instances.

Cricket uses the FuzzerView build its Network of workers, and communicate with
the workers.

Network:

The Network struct groups together the FuzzerView to give a logical ordering
of the Fuzzer network structure. It's possible to use Fuzzers directly, or in
a custom data structure of your choosing, but Network should be a good place to
start.

A Network can allow for more complex management of workers, but abstracted
through a graph-like datastructure, which is serializable to json, allowing you
to save and load networks.


Cricket currently does not use any machine learning, but the current model is
built to easily support it on multiple levels, allowing fine grained control
over even individual instances of a fuzzer on the system, retrieving fuzzer
stats, managing the frequency and magnitude of data transfers between systems,
and a few others things that should be useful. The docs will explain more when
I get a handle on that.
