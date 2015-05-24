// var ioClient        = require('socket.io-client')

// worker represents a 'worker node'. It has a hostname, which is the hostname
// associated with that system. A socket, which is a client socket for sending
// that worker messages. And it maintains an array of hosts that represent
// the workers that it communicates with.

var createWorker = function createWorker(objspec) {
    'use strict';
    var pushHost = function pushHost(hostName) {
        var i,
            j;
// Push host stores a hostName representing a node that a createWorker of this.hostName points to.
        for (i = 0, j = this.next_hosts.length; i < j; i += 1) {
            if (this.next_hosts[i] === hostName) {
                return;
            }
        }
        this.next_hosts.push(hostName);
    };
    return {
        hostName : objspec.hostName || undefined,
        socket : objspec.socket || undefined,
        next_hosts : [],
        pushHost : pushHost
    };
};

module.exports = {
    'createWorker' : createWorker
}
