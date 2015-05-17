"use strict";

// var ioClient        = require('socket.io-client')

// worker represents a 'worker node'. It has a hostname, which is the hostname
// associated with that system. A socket, which is a client socket for sending
// that worker messages. And it maintains an array of hosts that represent
// the workers that it communicates with.

var worker = function() {
  this.hostname;
  this.socket;
  this.next_hosts = [];
};

// push host stores a hostname representing a node that a worker of
// this.hostname points to.
worker.prototype.push_host = function(hostname){
  for(var i = 0; i < this.next_hosts.length; i++){
    if(this.next_hosts[i] === hostname){
      return;
    }
  }
  this.next_hosts.push(hostname);
}

exports.worker 	    = worker;
exports.push_host 	= worker.prototype.push_host;
