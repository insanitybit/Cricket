/*
	-M master node
	-W worker node
	--mp=[hostname + port]  Allows registering with a master node
	--qi=[time]	Sets the interval (in minutes) for sending queues
*/

"use strict";

var app					= require('http').createServer(),
		ioClient  	= require('socket.io-client'),
		io 					= require('socket.io')(app),
		worker			= require('./worker.js'),
    fs          = require('fs'),
		afl  				= require('./afl'),
		ini       	= require('ini')

var argv = require('minimist')(process.argv.slice(2));

var port = 8080;
var myhostname = require('os').hostname();
var config = '../config/';

var isMaster = false;


if(argv.M){
	isMaster = true;
}

if(argv.W){
	if(argv.mp !== undefined){
		var master = ioClient(argv.mp);
		master.emit('register', myhostname + ":" + port);
	}
}

app.listen(port);

afl.afl();
// afl.syncdir(myhostname);

var next_nodes 	= [];
var all_nodes 	= {};

/*
	These are the commands that workers will receive
*/

io.on('connection', function (socket) {
  console.log("new connection");


	// 'add_worker' event:
	// This event, when received, signals to add a 'hostname' to the
	// worker's next_nodes array, creating a client socket to it
  socket.on('add_worker', function (hostname){
		var tw = new worker.worker();
		tw.hostname = hostname;
		tw.socket = ioClient(hostname);
		next_nodes.push(tw);
  });

	socket.on('request_register', function (masterhost){
			var master = ioClient(masterhost);
			master.emit('register', myhostname + ":" + port);
  });

  socket.on('send_queue', function (){
    console.log("waterfall returns");ue

		var myQueue = afl.get_queue();

		next_nodes.forEach(function(node){
			//send each node queue
			node.emit('take_queue', myQueue);
		});

  });

	//

  socket.on('take_queue', function (queue){
		afl.write_queue(queue);
  });

	socket.on('start_work', function (aflargs, targetargs){
		console.log("Starting work");
		afl.start(aflargs, targetargs);
	});

});


// Events meant for the master

io.on('connection', function (socket) {


	// Allows other nodes to register with the master
	if(isMaster){
		socket.emit('request_register', myhostname);

		socket.on('register', function (hostname){
			console.log("registering new node: " + hostname);
			var tw = new worker.worker();
			tw.hostname = hostname;
			tw.socket = ioClient(hostname);
			all_nodes[hostname] = tw;
		});

	}

});

var readline = require('readline');

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// convert this to object/ map syntax eventually

rl.on('line', function (cmd) {
  switch(cmd){
		case "help":
			console.log("load\nlink\nwork\n"
			+ "stop\npassq\ndisplayall");
			break;

    case "load":
      loadlist();
      break;

    case "link":
      linknodes();
      break;

    case "work":
			startwork();
      break;

    case "stop":
      stopwork();
      break;

    case "passq":
      passq();
      break;

    case "displayall":
      displayall();
      break;

		case "pause":
			pause();
			break;

    default:
			console.log("load\nlink\nwork\n"
			+ "stop\npause\npassq\ndisplayall");
      break;
  }
});


/*
	Loads a file of hostnames in ./config/hosts
	Creates a client socket for each of these
*/
function loadlist(){
	var config  = ini.parse(fs.readFileSync('../config/config.ini', 'utf-8'));
  var hosts 	= config.hostnames.hosts;

  console.log("hosts read, pushing to nodelist");

  if(hosts.length === 0){
    console.log("no hosts found in file, nothing to do");
    return;
  }

	hosts.forEach(function(host){
		var tw = new worker.worker();
		tw.hostname = host;
		tw.socket		= ioClient(host);
		all_nodes[host] = tw;
	});
}


/*

	linknodes reads the pairs file, which is in format:
	host
	client
	host
	client
	[...]

	using the all_nodes map, emit to 'host' to connect to 'client'
	TODO: the pairs array is likely redundant, and adding extra copies
	remove it, and move hostnames directl into all_nodes
*/

function linknodes(){
	var tmp = fs.readFileSync(config + 'pairs').toString().split("\n");
	var pairs = [];

	for(var i = 0; i < tmp.length; i++){
		if(tmp[i] == "MASTER"){
			tmp[i] = myhostname + ':' + port;
		}
	}

	if((tmp.length < 1)){
		console.log("pairs is improperly formatted");
		return;
	}

	var index = 0;
	for (var i = 0; i < tmp.length; i+=2) {
		pairs.push({one:tmp[i], two:tmp[i+1]})
		// all_nodes[pairs[index].one].emit('add_worker', pairs[index].two);
		// all_nodes[pairs[index].one].push_host(pairs[index].two);
		// index++;
	}
}
/*

	pairs.push({one:tmp[i], two:tmp[i+1]});
	all_nodes[pairs[i].one].emit('add_worker', pairs[i].two);
	all_nodes[pairs[i].one].push_host(pairs[i].two);
*/



/*
	startwork emits the 'start_work' event to every worker in all_nodes
*/

function startwork(){
	var config     = ini.parse(fs.readFileSync('../config/config.ini', 'utf-8'));

	var aflargs = config.afl.args.aargs;
	if(aflargs == 'null')
		aflargs = [];

	var targs = config.target.args.targs;
	if(targs == 'null')
		targs = [];

	var interval = config.interval.minutes;

	interval = interval * 60 * 1000;

	Object.keys(all_nodes).forEach(function(key) {
		var val = all_nodes[key];

		// Tell the other workers it's time to start
		val.socket.emit('start_work', aflargs, targs);

		// val.socket.emit('start_work', aargs, targs);
	});

	afl.start(aflargs, targs);
	// afl.start(aflargs, targetargs);
	setInterval(function(){
		 console.log("emitting pass_queue");
			Object.keys(all_nodes).forEach(function(key) {
				var val = all_nodes[key];
				val.socket.emit('pass_queue');
			});
	}, interval);

}

function pause(){
	// TODO: Imlpement pause with the following logic,
	// Ctrl-C, then resume by replacing -i <dir> with -i-.
	// Also, make sure to pause queue interval
}

function stopwork(){

}

function passq(){
// do stuff
}

// show hostname + next_hosts of hostname
function displayall(){
	// console.log("There are " + all_nodes.size + " nodes");
	Object.keys(all_nodes).forEach(function(key) {
	  var val = all_nodes[key];
		for(var i = 0; i < val.next_hosts.length; i++){
			console.log("item " + all_nodes[i]);
		  console.log(val.hostname + "->" + val.next_hosts[i]);
		}
	});
}
